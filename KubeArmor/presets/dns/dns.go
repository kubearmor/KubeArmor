package dns

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/kubearmor/KubeArmor/KubeArmor/presets"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go socket ../../BPF/dnssocket.bpf.c -- -I/usr/include/ -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go dns ../../BPF/dnskprobe.bpf.c -- -I/usr/include/ -O2 -g

// add check for newer kernel versions
type DnsSocketObjs struct {
	Netns        uint32
	Objs         *dnssocketObjects
	RingBuf      *ringbuf.Reader
	Containerids []string
	SockFd       int
}

type containerinfo struct {
	Pid   int
	Pidns uint32
	Mntns uint32
	Netns uint32
}

type Dnspreset struct {
	presets.BasePreset
	Containers    map[string]containerinfo
	Dnskprobeobj  *dnskprobeObjects
	Kprobe        link.Link
	Dnscontainers *ebpf.Map
	DnsSocketObjs map[uint32]DnsSocketObjs
}

type namespaceKey struct {
	pidns uint32
	mntns uint32
}

func (p *Dnspreset) RegisterPreset() {
	pinpath := "/sys/fs/bpf"

	var err error

	p.Dnscontainers, err = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 256,
		Pinning:    ebpf.PinByName,
		Name:       "dns_container_maps",
	}, ebpf.MapOptions{
		PinPath: pinpath,
	})
	if err != nil {
		fmt.Printf("err pining container map: %v", err)
	}

	_, err = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    16,
		ValueSize:  48,
		MaxEntries: 128,
		Pinning:    ebpf.PinByName,
		Name:       "dns_shared_map",
	}, ebpf.MapOptions{
		PinPath: pinpath,
	})
	if err != nil {
		fmt.Printf("err pinning sharedmap: %v", err)
	}

	p.load_kprobe()
	// p.Dnscontainers = Dnscontainermap
}

func (p *Dnspreset) RegisterContainer(container tp.Container) {
	netns := getnetns(container.Pid)
	containerInfo := containerinfo{Pid: container.Pid, Pidns: container.PidNS, Mntns: container.PidNS, Netns: netns}
	p.Containers[container.ContainerID] = containerInfo
	fmt.Println("DNS container registered --> ", p.Containers[container.ContainerID])
}

func (p *Dnspreset) updateMapin(con containerinfo) {
	key := namespaceKey{pidns: con.Pidns, mntns: con.Pidns}
	value := uint32(1)
	if err := p.Dnscontainers.Put(key, value); err != nil {
		fmt.Printf("error adding container %s to outer map: %s", "", err)
	}
}

func (p *Dnspreset) deleteMap(con containerinfo) error {
	key := namespaceKey{pidns: con.Pidns, mntns: con.Pidns}
	if err := p.Dnscontainers.Delete(key); err != nil {
		fmt.Printf("error Deleting container %s to outer map: %s", "", err)
		return err
	}
	return nil
}

func (p *Dnspreset) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	for _, cid := range endPoint.Containers {
		container, ok := p.Containers[cid]
		if ok {
			p.updateMapin(container)
			p.AttachSocket(container.Pid, container.Netns, cid)
		}
	}
}

func (p *Dnspreset) Destroy() error {
	if err := p.Kprobe.Close(); err != nil {
		fmt.Printf("error destroying kprobe %s", err.Error())
	}

	for _, value := range p.DnsSocketObjs {
		sock := value.SockFd
		unix.Close(sock)
		value.Objs.Close()
	}

	return nil
}

func (p *Dnspreset) TraceEvents() {
	for _, net := range p.DnsSocketObjs {
		go lister(net.RingBuf)
	}

}

func (p *Dnspreset) UnregisterContainer(containerID string) {
	netns, preset := p.getNetnsOfContainerFromMap(containerID)
	if preset != 1 {
		fmt.Printf("containerid %s not being monitored", containerID)
	}

	err := p.removeContainer(netns, containerID)
	if err != 1 {
		fmt.Printf("containerid %s not being monitored", containerID)
	}

}
