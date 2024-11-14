package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func (p *Dnspreset) load_kprobe() error {
	pinpath := "/sys/fs/bpf"
	fn := "udp_sendmsg"
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := dnskprobeObjects{}
	p.Dnskprobeobj = &objs

	if err := loadDnskprobeObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
		},
	}); err != nil {
		fmt.Printf("err loading Dns objects: %v", err)
		return err
	}

	_, err := link.Kprobe(fn, objs.IgUdpSendmsg, nil)
	if err != nil {
		fmt.Printf("err opening kprobe: %s", err)
		return err
	}

	return nil
}

func (p *Dnspreset) AttachSocket(pid int, netns uint32, containerid string) {
	pinpath := "/sys/fs/bpf"

	objs := &dnssocketObjects{}
	spec, err := loadDnssocket()
	if err != nil {
		return
	}
	sock, _, err := p.openRawSock(pid, containerid)
	if err != nil {
		fmt.Printf("not able to open socket err: %s", err)
		return
	}

	consts := map[string]interface{}{
		"current_netns": netns,
	}
	if err := spec.RewriteConstants(consts); err != nil {
		fmt.Printf("RewriteConstants while attaching to pid %d err: %s ", pid, err)
		return
	}

	if err = spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
		},
	}); err != nil {
		fmt.Printf("\n err loading ebpf program: %s", err)
		return
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, objs.SimpleSocketHandler.FD()); err != nil {
		fmt.Printf("\nerr attaching BPF program: %s", err)
	}

	rd, err := ringbuf.NewReader(objs.SocketEvents)
	// rd, err := perf.NewReader(objs.SocketPerfEvent, 4096)
	if err != nil {
		fmt.Printf("\nerr opening ringbuf reader: %s", err)
	}

	dnsobjmap := DnsSocketObjs{}
	dnsobjmap.RingBuf = rd
	dnsobjmap.Objs = objs
	dnsobjmap.SockFd = sock
	dnsobjmap.Netns = netns
	dnsobjmap.Containerids = []string{containerid}
	p.DnsSocketObjs[netns] = dnsobjmap

	fmt.Println("attached socket for --> ", p.DnsSocketObjs[netns])

}

func (p *Dnspreset) openRawSock(pid int, containerid string) (int, int, error) {
	var netnamespace int

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, _ := netns.Get()
	defer origns.Close()

	netnsHandle, err := GetNetnsFromPid(pid)
	if err != nil {
		return -1, -1, err
	}
	defer netnsHandle.Close()

	var s unix.Stat_t
	if err := unix.Fstat(int(netnsHandle), &s); err != nil {
		fmt.Printf("\n->NS(%d)", s.Dev)
	}
	netnamespace = int(s.Ino)
	netns32 := uint32(netnamespace)

	//if we already have a socket open in this netns return and add the container in the array
	if sockobjs, ok := p.DnsSocketObjs[netns32]; ok {
		sockobjs.Containerids = append(sockobjs.Containerids, containerid)
		return -1, -1, errors.New("socket for this netns already created")
	}

	if err = netns.Set(netnsHandle); err != nil {
		return -1, -1, err
	}
	defer netns.Set(origns)

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, -1, err
	}

	sll := syscall.SockaddrLinklayer{
		Ifindex:  0,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return -1, -1, err
	}

	return sock, netnamespace, nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func GetNetnsFromPid(pid int) (netns.NsHandle, error) {
	return netns.GetFromPath(fmt.Sprintf("/proc/%d/ns/net", pid))
}

func getnetns(pid int) uint32 {
	pidstr := strconv.Itoa(pid)
	var netns uint32
	if data, err := os.Readlink("/proc/" + pidstr + "/ns/net"); err == nil {
		if _, err := fmt.Sscanf(data, "net:[%d]\n", &netns); err != nil {
			fmt.Println("Unable to get Netns (", pid, " ", err.Error(), ")")
			return 0
		}
	}

	return netns
}

func (p *Dnspreset) removeContainer(netns uint32, containerID string) int {
	var newobj []string

	if dnsock, ok := p.DnsSocketObjs[netns]; ok {
		if ispresent := slices.Contains(dnsock.Containerids, containerID); ispresent {
			newobj = removeString(dnsock.Containerids, containerID)
			con := p.Containers[containerID]

			//removing container from the map
			if err := p.deleteMap(con); err != nil {
				fmt.Printf("Error removing cotainer %s from dnsmap, err: %s ", containerID, err)
				return -1
			}
			fmt.Printf("DNS kprobe stopped monitoring containerid %s", containerID)

			//if no container in the specific netns, remove the socket
			if len(newobj) == 0 {
				sock := dnsock.SockFd
				unix.Close(sock)
				dnsock.Objs.Close()
				delete(p.DnsSocketObjs, netns)
				fmt.Printf("Socket from netns %d removed", netns)
			}

			return 1

		}
	}

	return -1
}

func (p *Dnspreset) getNetnsOfContainerFromMap(containerID string) (uint32, int) {
	if con, ok := p.Containers[containerID]; ok {
		return con.Netns, 1
	}
	return 0, -1
}

func removeString(slice []string, strToRemove string) []string {
	// Create a new slice to hold the filtered values
	var result []string
	for _, str := range slice {
		if str != strToRemove {
			result = append(result, str)
		}
	}
	return result
}

func lister(rd *ringbuf.Reader) {
	defer rd.Close()
	fmt.Println("started ringbuffer")
	for {
		record, err := rd.Read()

		if err != nil {

			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}

			log.Printf("reading from reader: %s", err)
			continue
		}

		fmt.Println("------------------")

		srcIP, ok := netip.AddrFromSlice(record.RawSample[4:8])
		if ok {
			fmt.Println("Source IP: ", srcIP.String()) // Expected: 255.255.255.252
		}

		dstIP, ok := netip.AddrFromSlice(record.RawSample[8:12])
		if ok {
			fmt.Println("Destination IP: ", dstIP.String()) // Expected: 75.75.75.120
		}

		SourcePort := binary.LittleEndian.Uint16(record.RawSample[16:18])
		DestPort := binary.LittleEndian.Uint16(record.RawSample[18:20])

		dnsoff := binary.BigEndian.Uint16(record.RawSample[20:22])
		dnslength := binary.BigEndian.Uint32(record.RawSample[22:28])
		netns := binary.LittleEndian.Uint32(record.RawSample[0:4])
		packetpresent := record.RawSample[28:29]

		fmt.Println("Netns : ", netns)
		fmt.Println("Source Port: ", SourcePort)                     //
		fmt.Println("Destination Port: ", DestPort)                  //
		fmt.Println("DNSoff : ", dnsoff)                             //
		fmt.Println("DNSlength : ", dnslength)                       //
		fmt.Println("Process information presetn : ", packetpresent) //
		fmt.Println("Packet : ", string(record.RawSample[38:]))      //
		// spew.Dump(record.RawSample[30:])
		parseDNSPacket(record.RawSample, 38)
		fmt.Println("--------------------")

	}

}

func parseDNSPacket(rawSample []byte, doff int) bool {
	var shoudlprint bool
	shoudlprint = false
	packetBytes := rawSample[doff:]

	dnsLayer := layers.DNS{}

	err := dnsLayer.DecodeFromBytes(packetBytes, nil)
	if err != nil {
		fmt.Println("decoding dns layer: %w", err)
		return shoudlprint
	}

	if len(dnsLayer.Questions) > 0 {

		for _, question := range dnsLayer.Questions {
			QType := question.Type.String()
			DNSName := string(question.Name) + "."
			fmt.Println("Question is Qtype ", QType, " DNS domain name", DNSName)
		}
		shoudlprint = true
	}
	if len(dnsLayer.Answers) > 0 {
		fmt.Println("********************")
		for _, answer := range dnsLayer.Answers {
			fmt.Println(" Answer \nIP is ", answer.IP.String())
			fmt.Println(" Domain ", string(answer.Name))
		}
		shoudlprint = true
	}
	return shoudlprint
}
