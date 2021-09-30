package main

import (
	docker "github.com/fsouza/go-dockerclient"
	"go.uber.org/zap"
	"inet.af/netaddr"
)

var (
	dockerLogger    = logger.Named("Docker")
	dockerNetworks  []string
	dockerClient    *docker.Client
	dockerNetIPSets = make(map[string]*netaddr.IPSet)
	dockerActiveIPs = &netaddr.IPSet{}
	dockerNewIP     = make(chan netaddr.IP, 64)
)

func dockerListen() (e error) {
	if dockerClient, e = docker.NewClientFromEnv(); e != nil {
		return e
	}
	events := make(chan *docker.APIEvents, 64)
	if e = dockerClient.AddEventListenerWithOptions(docker.EventsOptions{
		Filters: map[string][]string{
			"type":    {"network"},
			"event":   {"connect", "disconnect"},
			"network": dockerNetworks,
		},
	}, events); e != nil {
		return e
	}

	for _, network := range dockerNetworks {
		dockerRefreshNetwork(network, func(string) bool { return true })
	}

	go func() {
		for evt := range events {
			ctID := evt.Actor.Attributes["container"]
			dockerRefreshNetwork(evt.Actor.Attributes["name"],
				func(ct string) bool { return ct == ctID })
		}
	}()

	return nil
}

func dockerRefreshNetwork(name string, isNewContainer func(ctID string) bool) {
	network, e := dockerClient.NetworkInfo(name)
	if e != nil {
		dockerLogger.Warn("NetworkInfo error", zap.Error(e))
		return
	}

	var b netaddr.IPSetBuilder
	var ipAddrs []string
	var newIPs []netaddr.IP
	for ctID, ct := range network.Containers {
		prefix, _ := netaddr.ParseIPPrefix(ct.IPv6Address)
		ip := prefix.IP()
		b.Add(ip)
		ipAddrs = append(ipAddrs, ip.String())

		if isNewContainer(ctID) {
			newIPs = append(newIPs, ip)
		}
	}
	dockerLogger.Info("active IPs updated",
		zap.String("network", network.Name),
		zap.Strings("ip", ipAddrs),
	)
	dockerNetIPSets[network.ID], _ = b.IPSet()

	for net, ipset := range dockerNetIPSets {
		if net != network.ID {
			b.AddSet(ipset)
		}
	}
	dockerActiveIPs, _ = b.IPSet()

	for _, ip := range newIPs {
		dockerNewIP <- ip
	}
}
