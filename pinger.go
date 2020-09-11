/*
sendudp pre-generates a frame with a UDP packet with a payload of the given
size and starts sending it in and endless loop to given destination as fast as
possible.
*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"time"

	"github.com/asavie/xdp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
)

var PingCount int
var NIC string
var QueueID int
var SrcMAC string
var DstMAC string
var SrcIP string
var DstIP string
var SrcPort uint
var DstPort uint
var PayloadSize uint

func main() {

	flag.IntVar(&PingCount, "count", 5, "Number of Ping packets to send.")

	flag.StringVar(&NIC, "interface", "ens9", "Network interface to attach to.")
	flag.IntVar(&QueueID, "queue", 0, "The queue on the network interface to attach to.")
	flag.StringVar(&SrcMAC, "srcmac", "b2968175b211", "Source MAC address to use in sent frames.")
	flag.StringVar(&DstMAC, "dstmac", "ffffffffffff", "Destination MAC address to use in sent frames.")
	flag.StringVar(&SrcIP, "srcip", "192.168.111.10", "Source IP address to use in sent frames.")
	flag.StringVar(&DstIP, "dstip", "192.168.111.1", "Destination IP address to use in sent frames.")
	flag.UintVar(&SrcPort, "srcport", 1234, "Source UDP port.")
	flag.UintVar(&DstPort, "dstport", 1234, "Destination UDP port.")
	flag.UintVar(&PayloadSize, "payloadsize", 10, "Size of the UDP payload.")
	flag.Parse()

	// Initialize the XDP socket.

	link, err := netlink.LinkByName(NIC)
	if err != nil {
		panic(err)
	}

	xsk, err := xdp.NewSocket(link.Attrs().Index, QueueID)
	if err != nil {
		panic(err)
	}

	// Pre-generate a frame containing a DNS query.

	srcMAC, _ := hex.DecodeString(SrcMAC)
	dstMAC, _ := hex.DecodeString(DstMAC)

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC),
		DstMAC:       net.HardwareAddr(dstMAC),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       0,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.ParseIP(SrcIP).To4(),
		DstIP:    net.ParseIP(DstIP).To4(),
	}

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0),
		Id:       uint16(os.Getpid() & 0xffff),
		Seq:      1,
	}

	// udp.SetNetworkLayerForChecksum(ip)
	payload := make([]byte, PayloadSize)
	for i := 0; i < len(payload); i++ {
		payload[i] = byte(i)
	}

	// wm := icmp.Message{
	// 	Type: ipv6.ICMPTypeEchoRequest, Code: 0,
	// 	Body: &icmp.Echo{
	// 		ID: os.Getpid() & 0xffff, Seq: 1,
	// 		Data: []byte("HELLO-R-U-THERE"),
	// 	},
	// }
	// icmp_bytes, err := wm.Marshal(nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	fmt.Printf("sending icmp packets: %v (%v) to %v (%v)...\n", ip.SrcIP, eth.SrcMAC, ip.DstIP, eth.DstMAC)

	err = gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}
	frameLen := len(buf.Bytes())

	// buf.Bytes()[0x22] = 8
	// buf.Bytes()[0x23] = 0

	// Fill all the frames in UMEM with the pre-generated UDP packet.

	descs := xsk.GetDescs(math.MaxInt32)
	for i, _ := range descs {
		frameLen = copy(xsk.GetFrame(descs[i]), buf.Bytes())
	}

	// Start sending the pre-generated frame as quickly as possible in an
	// endless loop printing statistics of the number of sent frames and
	// the number of sent bytes every second.

	fmt.Printf("sending icmp packets: %v (%v) to %v (%v)...\n", ip.SrcIP, eth.SrcMAC, ip.DstIP, eth.DstMAC)

	go func() {
		var err error
		var prev xdp.Stats
		var cur xdp.Stats
		var numPkts uint64
		for i := uint64(0); ; i++ {
			time.Sleep(time.Duration(1) * time.Second)
			cur, err = xsk.Stats()
			if err != nil {
				panic(err)
			}
			numPkts = cur.Completed - prev.Completed
			fmt.Printf("%d packets/s (%d Mb/s)\n", numPkts, (numPkts*uint64(frameLen)*8)/(1000*1000))
			prev = cur
		}
	}()

	// var count = 0
	for i := 0; i < PingCount; i++ {
		fmt.Printf("Sending Ping Packet: %d\n", i)
		descs := xsk.GetDescs(1)
		for i, _ := range descs {
			descs[i].Len = uint32(frameLen)
		}
		xsk.Transmit(descs)

		_, _, err = xsk.Poll(-1)
		if err != nil {
			panic(err)
		}

		time.Sleep(time.Duration(150) * time.Millisecond)
	}
}

// package main

// import (
// 	"fmt"
// 	"log"
// 	"net"
// 	"syscall"

// 	"golang.org/x/sys/unix"
// )

// func main() {
// 	fd, err := syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
// 	fmt.Println("Fd: ", fd)

// 	err = syscall.Close(fd)
// 	if err != nil {
// 		panic(err)
// 	}
// }
