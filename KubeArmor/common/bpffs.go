// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package common

// This implementation for automounting bpffs has been inspired from
// Cilium - https://github.com/cilium/cilium/blob/master/pkg/bpf/bpffs_linux.go

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/mountinfo"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

var (
	// the default BPFFs mountpoint
	defaultBPFFsPath = "/sys/fs/bpf"

	// directory to fallback upon if default bpffs directory on host
	// had some other filesystem mounted
	fallbackBPFFsPath = "/run/kubearmor/bpffs"

	// path to where BPFFs is mounted
	// this is the final location where enforcer will save maps
	// after checking different mount points
	mapRoot = defaultBPFFsPath

	// for detecting misorder
	lockedDown = false
	once       sync.Once
	mountOnce  sync.Once
)

// CheckOrMountBPFFs checks for the mounted BPF filesystem at either
// the standard or the user specified custom location.
//   - No custom location specified, check if BPFFS mounted at
//     /sys/fs/bpf
//   - No - Mount BPFFS at /sys/fs/bpf
//   - Yes - We're done
//   - Yes but /sys/fs/bpf has a different fs mounted which implies
//     that kubearmor is running inside a container and the host
//     mount is an empty directory. So we mount BPFFS under
//     /run/kubearmor/bpffs.
//   - Custom location specified, check if BPFFS is mounted there
//   - No - Mount it
//   - Yes - We're done
//   - Yes but the location has some different fs mounted, return
//     an error
//
// We also check and error if there have been multiple mounts at
// the same point. See - https://patchwork.kernel.org/project/netdevbpf/patch/20220223131833.51991-1-laoar.shao@gmail.com/
func CheckOrMountBPFFs(bpfRoot string) {
	mountOnce.Do(func() {
		if err := checkOrMountBPFFs(bpfRoot); err != nil {
			kg.Err("Unable to mount BPF filesystem")
		}
	})
}

func checkOrMountBPFFs(bpfRoot string) error {
	if bpfRoot == defaultBPFFsPath {
		// mount BPFFs at the default path
		if err := checkOrMountDefaultLocations(); err != nil {
			return err
		}
	} else {
		// the user specified a custom path for BPFFs
		if err := checkOrMountCustomLocation(bpfRoot); err != nil {
			return err
		}
	}

	multipleMounts, err := hasMultipleMounts()
	if err != nil {
		return err
	}
	if multipleMounts {
		return fmt.Errorf("multiple mount points detected at %s", mapRoot)
	}

	return nil
}

func checkOrMountDefaultLocations() error {
	// Check whether /sys/fs/bpf has a BPFFS mount.
	mounted, bpffsInstance, err := mountinfo.IsMountFS(mountinfo.FilesystemTypeBPFFS, mapRoot)
	if err != nil {
		return err
	}

	// If /sys/fs/bpf is not mounted at all, we should mount
	// BPFFS there.
	if !mounted {
		kg.Printf("Mounting BPF Filesystem at %s", mapRoot)
		if err := mountFs(); err != nil {
			return err
		}

		return nil
	}

	if !bpffsInstance {
		// If /sys/fs/bpf has a mount but with some other filesystem
		// than BPFFS, it means that Kubearmor is running inside
		// container and /sys/fs/bpf is not mounted on host. So, we
		// mount BPFFS in /run/kubearmor/bpffs inside the container.
		// This will allow operation of Kubearmor but will result in
		// unmounting of the filesystem when the pod is restarted.
		kg.Warnf("BPF filesystem is going to be mounted automatically "+
			"in %s. However, it probably means that Kubearmor is running "+
			"inside container and BPFFS is not mounted on the host. ",
			mapRoot)

		if lockedDown {
			setMapRoot(mapRoot)
		}

		cMounted, cBpffsInstance, err := mountinfo.IsMountFS(mountinfo.FilesystemTypeBPFFS, mapRoot)
		if err != nil {
			return err
		}
		if !cMounted {
			kg.Printf("Mounting BPF Filesystem at %s", mapRoot)
			if err := mountFs(); err != nil {
				return err
			}
		} else if !cBpffsInstance {
			kg.Printf("%s is mounted but has a different filesystem than BPFFS", fallbackBPFFsPath)
		}
	}

	kg.Printf("Detected mounted BPF filesystem at %s", mapRoot)

	return nil
}

func checkOrMountCustomLocation(bpfRoot string) error {
	setMapRoot(bpfRoot)

	// Check whether the custom location has a BPFFS mount.
	mounted, bpffsInstance, err := mountinfo.IsMountFS(mountinfo.FilesystemTypeBPFFS, bpfRoot)
	if err != nil {
		return err
	}

	// If the custom location has no mount, let's mount BPFFS there.
	if !mounted {
		setMapRoot(bpfRoot)
		kg.Printf("Mounting BPF Filesystem at %s", mapRoot)
		if err := mountFs(); err != nil {
			return err
		}

		return nil
	}

	// If the custom location already has a mount with some other filesystem than
	// BPFFS, return the error.
	if !bpffsInstance {
		return fmt.Errorf("mount in the custom directory %s has a different filesystem than BPFFS", bpfRoot)
	}

	kg.Printf("Detected mounted BPF filesystem at %s", mapRoot)

	return nil
}

// hasMultipleMounts checks whether the current mapRoot has only one mount.
func hasMultipleMounts() (bool, error) {
	num := 0

	mountInfos, err := mountinfo.GetMountInfo()
	if err != nil {
		return false, err
	}

	for _, mountInfo := range mountInfos {
		if mountInfo.Root == "/" && mountInfo.MountPoint == mapRoot {
			num++
		}
	}

	return num > 1, nil
}

// mounts BPFFS into mapRoot directory
func mountFs() error {
	mapRootStat, err := os.Stat(mapRoot)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(mapRoot, 0750); err != nil {
				return fmt.Errorf("unable to create bpf mount directory: %s", err)
			}
		} else {
			return fmt.Errorf("failed to stat the mount path %s: %s", mapRoot, err)

		}
	} else if !mapRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", mapRoot)
	}

	if err := unix.Mount(mapRoot, mapRoot, "bpf", 0, ""); err != nil {
		return fmt.Errorf("failed to mount %s: %s", mapRoot, err)
	}
	return nil
}

func lockDown() {
	lockedDown = true
}

func setMapRoot(path string) {
	// we don't want to change the path on which maps are stored to
	// be changed once we start writing maps
	if lockedDown {
		panic("setMapRoot() call after MapRoot was read")
	}
	mapRoot = path
}

// GetMapRoot function returns the current mapRoot path
func GetMapRoot() string {
	once.Do(lockDown)
	return mapRoot
}
