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
	flag.UintVar(&PayloadSize, "payloadsize", 10, "Size of the payload.")
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

	defer xsk.Close()

	// Pre-generate a frame
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

	// add payload
	payload := make([]byte, PayloadSize)
	for i := 0; i < len(payload); i++ {
		payload[i] = byte(i)
	}

	// serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, eth, ip, icmp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}
	frameLen := len(buf.Bytes())

	// Fill all the frames in UMEM with the pre-generated packet.
	descs := xsk.GetDescs(math.MaxInt32)
	for i, _ := range descs {
		frameLen = copy(xsk.GetFrame(descs[i]), buf.Bytes())
	}

	// go func() {
	// 	var err error
	// 	var prev xdp.Stats
	// 	var cur xdp.Stats
	// 	var numPkts uint64
	// 	for i := uint64(0); ; i++ {
	// 		time.Sleep(time.Duration(1) * time.Second)
	// 		cur, err = xsk.Stats()
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		numPkts = cur.Completed - prev.Completed
	// 		fmt.Printf("%d packets/s (%d Mb/s)\n", numPkts, (numPkts*uint64(frameLen)*8)/(1000*1000))
	// 		prev = cur
	// 	}
	// }()

	fmt.Printf("sending icmp packets: %v (%v) to %v (%v)...\n", ip.SrcIP, eth.SrcMAC, ip.DstIP, eth.DstMAC)

	// transmit
	for i := 0; i < PingCount; i++ {

		descs := xsk.GetDescs(xsk.NumFreeTxSlots())
		if len(descs) > 0 {
			fmt.Printf("Sending Ping Packet: %d\n", i)

			for j, _ := range descs {
				descs[j].Len = uint32(frameLen)
			}

			numPosted := xsk.Transmit(descs)
			_, numCompleted, err := xsk.Poll(1)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Transmitted packets: %d posted, %d transmitted\n", numPosted, -1)
		}
		time.Sleep(time.Duration(150) * time.Millisecond)
	}
}
