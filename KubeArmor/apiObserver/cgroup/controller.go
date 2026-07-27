// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package cgroup provides Kubeshark-style cgroup-based pod targeting for the
// API Observer.
//
// When a pod is created or deleted, the controller updates the ka_cgroup_ids
// BPF map so the cgroup_skb packet sniffer automatically starts or stops
// capturing traffic for that pod's cgroup.
//
// It also manages attaching and detaching the cgroup_skb BPF programs to each
// pod's cgroup directory when CGROUPV2_DIRECT_ATTACH mode is used.
package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	// cgroupFSRoot is the standard cgroup v2 mount point as seen inside the pod.
	cgroupFSRoot = "/sys/fs/cgroup"

	// CONFIGURATION_PASS_ALL_CGROUPS enables observe-all mode in the BPF settings map.
	// When set, ALL cgroups are observed except those in ka_excluded_cgroup_ids.
	CONFIGURATION_PASS_ALL_CGROUPS = 1 << 1
)


// FindHostCgroupRoot returns the path to the host's cgroup v2 root,
// bypassing any private cgroup namespace the pod may be running in.
// Exported so other packages (e.g. apiObserver) can build correct cgroup paths.
func FindHostCgroupRoot() string {
	candidates := []string{
		"/proc/1/root/sys/fs/cgroup", // bypass cgroup namespace via host init
		cgroupFSRoot,                  // fallback: container's view
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return cgroupFSRoot
}

// searchMountpointFromHost scans /proc/<pid>/mountinfo looking for a cgroup2
// filesystem mounted from the host root (mountRoot == "/"). This mirrors the
// Kubeshark tracer approach (pkg/mount/mount.go:SearchMountpointFromHost).
// Use pid=1 to read from the host init process when hostPID=true.
func searchMountpointFromHost(mountinfoPath string) string {
	f, err := os.Open(mountinfoPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// mountinfo format:
		// mountID parentID major:minor mountRoot mountPoint mountOptions [optionals] - fsType source superOptions
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		mountRoot := fields[3]
		mountPoint := fields[4]

		// Find "-" separator
		sepIdx := -1
		for i, f := range fields {
			if f == "-" {
				sepIdx = i
				break
			}
		}
		if sepIdx < 0 || sepIdx+1 >= len(fields) {
			continue
		}
		fsType := fields[sepIdx+1]

		// cgroup2 mounted from the host root (mountRoot="/") is the full hierarchy.
		if fsType == "cgroup2" && mountRoot == "/" {
			return mountPoint
		}
	}
	return ""
}

// Controller manages cgroup targeting for the packet sniffer.
// It maintains the ka_cgroup_ids map in sync with the set of observed pods.
type Controller struct {
	mu sync.Mutex

	// BPF maps.
	cgroupIDs         *ebpf.Map // ka_cgroup_ids
	excludedCgroupIDs *ebpf.Map // ka_excluded_cgroup_ids
	settings          *ebpf.Map // ka_settings

	// BPF programs for cgroup_skb attachment.
	ingressProg *ebpf.Program // SEC("cgroup_skb/ingress")
	egressProg  *ebpf.Program // SEC("cgroup_skb/egress")

	// Per-cgroup attachment links (for cleanup on pod removal).
	cgroupLinks map[uint64][]link.Link
}

// Config carries the BPF maps and programs needed by the Controller.
type Config struct {
	CgroupIDsMap         *ebpf.Map
	ExcludedCgroupIDsMap *ebpf.Map
	SettingsMap          *ebpf.Map
	IngressProg          *ebpf.Program
	EgressProg           *ebpf.Program
}

// New creates a CgroupController with the given BPF maps and programs.
func New(cfg Config) *Controller {
	return &Controller{
		cgroupIDs:         cfg.CgroupIDsMap,
		excludedCgroupIDs: cfg.ExcludedCgroupIDsMap,
		settings:          cfg.SettingsMap,
		ingressProg:       cfg.IngressProg,
		egressProg:        cfg.EgressProg,
		cgroupLinks:       make(map[uint64][]link.Link),
	}
}

// AttachRoot attaches cgroup_skb/ingress and cgroup_skb/egress programs to the
// host's root cgroup directory. This causes the BPF programs to run
// for ALL sockets on the node, with the BPF-side cgroup filter
// (ka_should_target_cgroup) deciding per-packet which cgroups to observe.
//
// Key subtlety: pods run in private cgroup namespaces, so /sys/fs/cgroup
// inside the pod corresponds to the pod's OWN cgroup root, not the host root.
// We use FindHostCgroupRoot() to bypass this and attach to the true host root.
//
// This MUST be called before any traffic is expected. Without it, the BPF
// programs are loaded but have no attachment point and are never invoked.
func (c *Controller) AttachRoot() (string, error) {
	root := FindHostCgroupRoot()
	links, err := c.attachToCgroup(root)
	if err != nil {
		return root, fmt.Errorf("AttachRoot(%s): %w", root, err)
	}
	// Store root links under cgroup ID 0 (sentinel for root).
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.cgroupLinks[0]; ok {
		for _, l := range existing {
			l.Close()
		}
	}
	c.cgroupLinks[0] = links
	return root, nil
}

// SetPassAllMode enables or disables observe-all-cgroups mode.
// In pass-all mode, all cgroups are observed except those in the excluded set.
// In selective mode (default), only cgroups in ka_cgroup_ids are observed.
func (c *Controller) SetPassAllMode(enabled bool) error {
	type kaConfig struct {
		Flags uint32
		_     uint32
	}
	var cfg kaConfig
	if enabled {
		cfg.Flags |= CONFIGURATION_PASS_ALL_CGROUPS
	}
	key := uint32(0)
	return c.settings.Put(key, cfg)
}

// TargetCgroup adds a cgroup ID to the observed set.
//
// cgroupID is the kernel cgroup ID (from /proc/<pid>/cgroup or bpf_get_current_cgroup_id).
func (c *Controller) TargetCgroup(cgroupID uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Add to BPF map so cgroup_skb programs filter in this cgroup.
	val := uint32(1)
	if err := c.cgroupIDs.Put(cgroupID, val); err != nil {
		return fmt.Errorf("cgroup.Controller: updating ka_cgroup_ids: %w", err)
	}

	// cgroup_skb programs are globally attached to the root cgroup via AttachRoot().
	// No per-cgroup attachment needed — BPF filters by cgroup ID at packet time.

	return nil
}

// UntargetCgroup removes a cgroup from the observed set and detaches the
// cgroup_skb programs.
func (c *Controller) UntargetCgroup(cgroupID uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove from BPF map.
	if err := c.cgroupIDs.Delete(cgroupID); err != nil && !isNotFound(err) {
		return fmt.Errorf("cgroup.Controller: removing from ka_cgroup_ids: %w", err)
	}

	// cgroup_skb programs are globally attached; no per-cgroup links to detach.

	return nil
}

// ExcludeCgroup adds a cgroup to the excluded set (used in pass-all mode).
func (c *Controller) ExcludeCgroup(cgroupID uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	val := uint32(1)
	return c.excludedCgroupIDs.Put(cgroupID, val)
}

// Close releases all cgroup_skb links.
func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, links := range c.cgroupLinks {
		for _, l := range links {
			l.Close()
		}
	}
	c.cgroupLinks = make(map[uint64][]link.Link)
}

// attachToCgroup attaches cgroup_skb/ingress and cgroup_skb/egress programs
// to the given cgroup directory path.
func (c *Controller) attachToCgroup(cgroupPath string) ([]link.Link, error) {
	path := cgroupPath
	if !filepath.IsAbs(path) {
		path = filepath.Join(cgroupFSRoot, path)
	}

	dir, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cgroup dir %s: %w", path, err)
	}
	defer dir.Close()

	var links []link.Link

	if c.ingressProg != nil {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    path,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: c.ingressProg,
		})
		if err != nil {
			// Close any already-opened links before returning error.
			for _, lk := range links {
				lk.Close()
			}
			return nil, fmt.Errorf("attach ingress to %s: %w", path, err)
		}
		links = append(links, l)
	}

	if c.egressProg != nil {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    path,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: c.egressProg,
		})
		if err != nil {
			for _, lk := range links {
				lk.Close()
			}
			return nil, fmt.Errorf("attach egress to %s: %w", path, err)
		}
		links = append(links, l)
	}

	return links, nil
}

// isNotFound returns true for ebpf.ErrKeyNotExist and related "not found" errors.
func isNotFound(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}
