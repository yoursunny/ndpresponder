package main

import (
	"net"
	"os/exec"
	"time"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

// HostInfo contains address information of the host machine.
type HostInfo struct {
	HostMAC   net.HardwareAddr
	GatewayIP netaddr.IP
}

func gatherHostInfo() (hi HostInfo, e error) {
	logEntry := logger.Named("HostInfo")
	hi.HostMAC = netif.HardwareAddr
	logEntry.Info("found MAC", zap.Stringer("mac", hi.HostMAC))

	nl, e := netlink.NewHandle()
	if e != nil {
		logEntry.Error("netlink.NewHandle error", zap.Error(e))
		return hi, nil
	}
	defer nl.Close()

	link, e := nl.LinkByIndex(netif.Index)
	if e != nil {
		logEntry.Error("netlink.LinkByIndex error", zap.Error(e))
		return hi, nil
	}
	routes, e := nl.RouteList(link, unix.AF_INET6)
	if e != nil {
		logEntry.Error("netlink.RouteList error", zap.Error(e))
		return hi, nil
	}
	for _, route := range routes {
		if route.Dst == nil {
			hi.GatewayIP, _ = netaddr.FromStdIP(route.Gw)
		}
	}
	if hi.GatewayIP.IsZero() {
		logEntry.Warn("no default gateway")
		return hi, nil
	}
	logEntry.Info("found gateway", zap.Stringer("gateway", hi.GatewayIP))

	var gatewayNeigh *netlink.Neigh
	for {
		neighs, e := nl.NeighList(netif.Index, unix.AF_INET6)
		if e != nil {
			logEntry.Error("netlink.NeighList error", zap.Error(e))
			return hi, nil
		}
		for _, neigh := range neighs {
			ip, _ := netaddr.FromStdIP(neigh.IP)
			if ip != hi.GatewayIP || len(neigh.HardwareAddr) != 6 {
				continue
			}
			switch neigh.State {
			case unix.NUD_REACHABLE, unix.NUD_NOARP:
				gatewayNeigh = &neigh
				goto NEIGH_SET
			case unix.NUD_PERMANENT:
				goto NEIGH_SKIP
			}
		}

		exec.Command("/usr/bin/ping", "-c", "1", hi.GatewayIP.String()).Run()
		logEntry.Debug("waiting for gateway neigh entry")
		time.Sleep(time.Second)
	}

NEIGH_SET:
	gatewayNeigh.State = unix.NUD_NOARP
	if e = nl.NeighSet(gatewayNeigh); e != nil {
		logEntry.Error("netlink.NeighSet error", zap.Error(e))
	} else {
		logEntry.Info("netlink.NeighSet OK", zap.Stringer("lladdr", gatewayNeigh.HardwareAddr))
	}
NEIGH_SKIP:

	return hi, nil
}
