package pinger

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/dropbox/goebpf"
)

// In sync with xdp_dump.c  "struct perf_event_item"
type perfEventItem struct {
	ID, Seq  uint16
	OrigTime uint32
	RecTime  uint64
}

const (
	// Size of structure used to pass metadata
	metadataSize = 16
)

func KickOffPinger(ip string, perfmap goebpf.Map) chan bool {

	quit := make(chan bool)

	// start go routine
	go func() {
		// Start listening to Perf Events
		perf, _ := goebpf.NewPerfEvents(perfmap)
		perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
		if err != nil {
			fatalError("perf.StartForAllProcessesAndCPUs(): %v", err)
		}

		var event perfEventItem

		for {
			eventData, ok := <-perfEvents
			switch {
			case ok:

				reader := bytes.NewReader(eventData)
				fmt.Printf("%+v\n", reader)
				binary.Read(reader, binary.BigEndian, &event)

				fmt.Printf("ID: %v,\nSequence: %v,\nOriginate Timestamp: %v,\nRecieve Timestamp: %v \n",
					event.ID, event.Seq,
					event.OrigTime, event.RecTime,
				)
				if len(eventData)-metadataSize > 0 {
					// event contains packet sample as well
					fmt.Println(hex.Dump(eventData[metadataSize:]))
				}

			case <-quit:

				// Stop perf events and print summary
				perf.Stop()
				fmt.Println("\nSummary:")
				fmt.Printf("\t%d Event(s) Received\n", perf.EventsReceived)
				fmt.Printf("\t%d Event(s) lost (e.g. small buffer, delays in processing)\n", perf.EventsLost)
				fmt.Println("\nDetaching program and exit...")
				return

			}
		}

	}()

	// send the initial ping
	ping(ip)

	return quit
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func ping(ip string) {
	var err error
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)

	addr := syscall.SockaddrInet4{Port: 0}

	copy(addr.Addr[:], net.ParseIP(ip))

	p := pkt(ip)
	err = syscall.Sendto(fd, p, 0, &addr)
	if err != nil {
		fatalError("Sendto failed:", err)
	}
}

func pkt(ip string) []byte {

	h := Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + 10, // 20 bytes for IP, 10 for ICMP
		TTL:      64,
		Protocol: 1, // ICMP
		Dst:      net.ParseIP(ip),
	}

	icmp := []byte{
		8, // type: echo request
		0, // code: not used by echo request
		0, // checksum (16 bit), we fill in below
		0,
		0, // identifier (16 bit). zero allowed.
		0,
		0, // sequence number (16 bit). zero allowed.
		0,
		0xC0, // Optional data. ping puts time packet sent here
		0xDE,
	}
	cs := csum(icmp)
	icmp[2] = byte(cs)
	icmp[3] = byte(cs >> 8)

	out, err := h.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	return append(out, icmp...)
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	// add back the carry
	s = s>>16 + s&0xffff
	s = s + s>>16
	return uint16(^s)
}
