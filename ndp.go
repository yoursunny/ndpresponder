package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"inet.af/netaddr"
)

// tcpdump -dd 'icmp6 && ip6[40]==135'
var bpfFilter = []bpf.RawInstruction{
	{0x28, 0, 0, 0x0000000c},
	{0x15, 0, 8, 0x000086dd},
	{0x30, 0, 0, 0x00000014},
	{0x15, 3, 0, 0x0000003a},
	{0x15, 0, 5, 0x0000002c},
	{0x30, 0, 0, 0x00000036},
	{0x15, 0, 3, 0x0000003a},
	{0x30, 0, 0, 0x00000036},
	{0x15, 0, 1, 0x00000087},
	{0x6, 0, 0, 0x00040000},
	{0x6, 0, 0, 0x00000000},
}

var advertTypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0)

// NeighSolicitation contains information from an ICMPv6 neighbor solicitation packet.
type NeighSolicitation struct {
	RouterMAC [6]byte
	RouterIP  netaddr.IP
	TargetIP  netaddr.IP
}

func (ns NeighSolicitation) String() string {
	return fmt.Sprintf("who has %s tell %s at %02x:%02x:%02x:%02x:%02x:%02x",
		ns.TargetIP, ns.RouterIP,
		ns.RouterMAC[0], ns.RouterMAC[1], ns.RouterMAC[2], ns.RouterMAC[3], ns.RouterMAC[4], ns.RouterMAC[5])
}

// Respond creates an ICMPv6 neighbor advertisement packet.
func (ns NeighSolicitation) Respond(w gopacket.SerializeBuffer, hostMAC net.HardwareAddr) error {
	eth := layers.Ethernet{
		SrcMAC:       hostMAC,
		DstMAC:       net.HardwareAddr(ns.RouterMAC[:]),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip6 := layers.IPv6{
		Version:    6,
		SrcIP:      ns.TargetIP.IPAddr().IP,
		DstIP:      ns.RouterIP.IPAddr().IP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   math.MaxUint8,
	}

	icmp6 := layers.ICMPv6{
		TypeCode: advertTypeCode,
	}
	icmp6.SetNetworkLayerForChecksum(&ip6)

	advert := layers.ICMPv6NeighborAdvertisement{
		Flags:         0x80 | 0x40, // router, solicited
		TargetAddress: ns.TargetIP.IPAddr().IP,
		Options: layers.ICMPv6Options{
			{
				Type: layers.ICMPv6OptTargetAddress,
				Data: []byte(hostMAC),
			},
		},
	}

	return gopacket.SerializeLayers(w, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &eth, &ip6, &icmp6, &advert)
}

// CaptureNeighSolicitation captures ICMPv6 neighbor solicitation packets.
func CaptureNeighSolicitation(src gopacket.ZeroCopyPacketDataSource) <-chan NeighSolicitation {
	ch := make(chan NeighSolicitation)
	go func() {
		var eth layers.Ethernet
		var ip6 layers.IPv6
		var icmp6 layers.ICMPv6
		var solicit layers.ICMPv6NeighborSolicitation
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &icmp6, &solicit)
		decoded := []gopacket.LayerType{}

		for {
			pkt, _, e := src.ZeroCopyReadPacketData()
			if errors.Is(e, io.EOF) {
				close(ch)
				return
			}

			if e := parser.DecodeLayers(pkt, &decoded); e != nil {
				continue
			}

			if len(decoded) == 4 && decoded[3] == layers.LayerTypeICMPv6NeighborSolicitation {
				ns := NeighSolicitation{}
				copy(ns.RouterMAC[:], eth.SrcMAC)
				ns.RouterIP, _ = netaddr.FromStdIP(ip6.SrcIP)
				ns.TargetIP, _ = netaddr.FromStdIP(solicit.TargetAddress)
				ch <- ns
			}
		}
	}()
	return ch
}
