package main

import (
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"inet.af/netaddr"
)

var logger = func() *zap.Logger {
	var lvl zapcore.Level
	if environ, ok := os.LookupEnv("NDPRESPONDER_LOG"); ok {
		lvl.Set(environ)
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		os.Stderr,
		lvl,
	)
	return zap.New(core)
}()

var (
	netif         *net.Interface
	targetSubnets *netaddr.IPSet
	handle        *afpacket.TPacket
)

var app = &cli.App{
	Name:        "ndpresponder",
	Description: "IPv6 Neighbor Discovery Responder",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "ifname",
			Aliases:  []string{"i"},
			Usage:    "uplink network interface",
			Required: true,
		},
		&cli.StringSliceFlag{
			Name:    "subnet",
			Aliases: []string{"n"},
			Usage:   "static target subnet",
		},
		&cli.StringSliceFlag{
			Name:    "docker-network",
			Aliases: []string{"N"},
			Usage:   "Docker network name",
		},
	},
	HideHelpCommand: true,
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
		targetSubnets, e = ipset.IPSet()
		if e != nil {
			return cli.Exit(e, 1)
		}

		dockerNetworks = c.StringSlice("docker-network")

		return nil
	},
	Action: func(c *cli.Context) error {
		hi, e := gatherHostInfo()
		if e != nil {
			return cli.Exit(e, 1)
		}
		h, e := afpacket.NewTPacket(afpacket.OptInterface(netif.Name))
		if e != nil {
			return cli.Exit(e, 1)
		}
		if e = h.SetBPF(bpfFilter); e != nil {
			return cli.Exit(e, 1)
		}
		solicitations := CaptureNeighSolicitation(h)

		if len(dockerNetworks) > 0 {
			if e = dockerListen(); e != nil {
				return cli.Exit(e, 1)
			}
		}

		sbuf := gopacket.NewSerializeBuffer()
	L:
		for {
			select {
			case ns := <-solicitations:
				logEntry := logger.With(zap.Stringer("ns", ns))
				switch {
				case dockerActiveIPs.Contains(ns.TargetIP):
					logEntry = logEntry.With(zap.String("reason", "docker"))
				case ns.DestIP.IsMulticast() && targetSubnets.Contains(ns.TargetIP):
					logEntry = logEntry.With(zap.String("reason", "static"))
				default:
					logEntry.Debug("IGNORE")
					continue L
				}

				if e := ns.Respond(sbuf, hi); e != nil {
					logEntry.Warn("RESPOND error", zap.Error(e))
					continue L
				}
				logEntry.Info("RESPOND")
				h.WritePacketData(sbuf.Bytes())

			case ip := <-dockerNewIP:
				logEntry := logger.With(zap.Stringer("ip", ip))
				if e := Gratuitous(sbuf, hi, ip); e != nil {
					logEntry.Warn("GRATUITOUS error", zap.Error(e))
					continue L
				}
				logEntry.Info("GRATUITOUS")
				h.WritePacketData(sbuf.Bytes())

				if hi.GatewayIP.IsZero() {
					break
				}
				if e := Solicit(sbuf, hi, ip); e != nil {
					logEntry.Warn("SOLICIT error", zap.Error(e))
					continue L
				}
				logEntry.Info("SOLICIT")
				h.WritePacketData(sbuf.Bytes())
			}
		}
	},
	After: func(c *cli.Context) error {
		if handle != nil {
			handle.Close()
		}
		return nil
	},
}

func main() {
	rand.Seed(time.Now().UnixNano())
	app.Run(os.Args)
}
