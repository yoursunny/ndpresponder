package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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
var packetSerializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}
var solicitTypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0)
var advertTypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0)

// Gratuitous creates a gratuitous ICMPv6 neighbor solicitation packet.
func Gratuitous(w gopacket.SerializeBuffer, hi HostInfo, targetIP netaddr.IP) error {
	ip16 := targetIP.As16()
	eth := layers.Ethernet{
		SrcMAC:       hi.HostMAC,
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0xFF, ip16[13], ip16[14], ip16[15]},
		EthernetType: layers.EthernetTypeIPv6,
	}

	dstIP := net.IP{0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0xFF, ip16[13], ip16[14], ip16[15]}
	ip6 := layers.IPv6{
		Version:    6,
		SrcIP:      make(net.IP, net.IPv6len),
		DstIP:      dstIP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   math.MaxUint8,
	}

	icmp6 := layers.ICMPv6{
		TypeCode: solicitTypeCode,
	}
	icmp6.SetNetworkLayerForChecksum(&ip6)

	nonce := make([]byte, 6)
	rand.Read(nonce)
	solicit := layers.ICMPv6NeighborSolicitation{
		TargetAddress: targetIP.IPAddr().IP,
		Options: layers.ICMPv6Options{
			{
				Type: 0x0E,
				Data: nonce,
			},
		},
	}

	return gopacket.SerializeLayers(w, packetSerializeOpts, &eth, &ip6, &icmp6, &solicit)

}

// Solicit creates an ICMPv6 neighbor solicitation packet.
func Solicit(w gopacket.SerializeBuffer, hi HostInfo, sourceIP netaddr.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       hi.HostMAC,
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0xFF, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv6,
	}

	dstIP := net.IP{0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x01}
	ip6 := layers.IPv6{
		Version:    6,
		SrcIP:      sourceIP.IPAddr().IP,
		DstIP:      dstIP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   math.MaxUint8,
	}

	icmp6 := layers.ICMPv6{
		TypeCode: solicitTypeCode,
	}
	icmp6.SetNetworkLayerForChecksum(&ip6)

	nonce := make([]byte, 6)
	rand.Read(nonce)
	solicit := layers.ICMPv6NeighborSolicitation{
		TargetAddress: hi.GatewayIP.IPAddr().IP,
		Options: layers.ICMPv6Options{
			{
				Type: layers.ICMPv6OptSourceAddress,
				Data: []byte(hi.HostMAC),
			},
		},
	}

	return gopacket.SerializeLayers(w, packetSerializeOpts, &eth, &ip6, &icmp6, &solicit)
}

// NeighSolicitation contains information from an ICMPv6 neighbor solicitation packet.
type NeighSolicitation struct {
	RouterMAC [6]byte
	RouterIP  netaddr.IP
	DestIP    netaddr.IP
	TargetIP  netaddr.IP
}

func (ns NeighSolicitation) String() string {
	if ns.DestIP.IsMulticast() {
		return fmt.Sprintf("who-has %s tell %s", ns.TargetIP, ns.RouterIP)
	}
	return fmt.Sprintf("is-alive %s tell %s", ns.TargetIP, ns.RouterIP)
}

// Respond creates an ICMPv6 neighbor advertisement packet.
func (ns NeighSolicitation) Respond(w gopacket.SerializeBuffer, hi HostInfo) error {
	eth := layers.Ethernet{
		SrcMAC:       hi.HostMAC,
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

	var advertFlags uint8 = 0x80 | 0x40 // router, solicited
	if ns.DestIP.IsMulticast() {
		advertFlags |= 0x20 // override
	}
	advert := layers.ICMPv6NeighborAdvertisement{
		Flags:         advertFlags,
		TargetAddress: ns.TargetIP.IPAddr().IP,
		Options: layers.ICMPv6Options{
			{
				Type: layers.ICMPv6OptTargetAddress,
				Data: []byte(hi.HostMAC),
			},
		},
	}

	return gopacket.SerializeLayers(w, packetSerializeOpts, &eth, &ip6, &icmp6, &advert)
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
				ns.DestIP, _ = netaddr.FromStdIP(ip6.DstIP)
				ns.TargetIP, _ = netaddr.FromStdIP(solicit.TargetAddress)
				ch <- ns
			}
		}
	}()
	return ch
}
