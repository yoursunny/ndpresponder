package main

import (
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/urfave/cli/v2"
	"inet.af/netaddr"
)

var (
	netif        *net.Interface
	acceptTarget *netaddr.IPSet
	handle       *afpacket.TPacket
)

var app = &cli.App{
	Name: "ndpresponder",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "ifname",
			Aliases:  []string{"i"},
			Required: true,
		},
		&cli.StringSliceFlag{
			Name:     "subnet",
			Aliases:  []string{"n"},
			Required: true,
		},
	},
	Before: func(c *cli.Context) (e error) {
		if netif, e = net.InterfaceByName(c.String("ifname")); e != nil {
			return cli.Exit(e, 1)
		}

		var ipset netaddr.IPSetBuilder
		for _, subnet := range c.StringSlice("subnet") {
			prefix, e := netaddr.ParseIPPrefix(subnet)
			if e != nil {
				return cli.Exit(e, 1)
			}
			ipset.AddPrefix(prefix)
		}
		acceptTarget = ipset.IPSet()

		return nil
	},
	Action: func(c *cli.Context) error {
		h, e := afpacket.NewTPacket(afpacket.OptInterface(netif.Name))
		if e != nil {
			return cli.Exit(e, 1)
		}
		if e = h.SetBPF(bpfFilter); e != nil {
			return cli.Exit(e, 1)
		}

		sbuf := gopacket.NewSerializeBuffer()
		for ns := range CaptureNeighSolicitation(h) {
			if !acceptTarget.Contains(ns.TargetIP) {
				log.Println("IGNORE", ns)
				continue
			}

			log.Println("RESPOND", ns)
			if e := ns.Respond(sbuf, netif.HardwareAddr); e != nil {
				continue
			}
			h.WritePacketData(sbuf.Bytes())
		}
		return nil
	},
	After: func(c *cli.Context) error {
		if handle != nil {
			handle.Close()
		}
		return nil
	},
}

func main() {
	app.Run(os.Args)
}
