# IPv6 Neighbor Discovery Responder

**ndpresponder** is a Go program that listens for ICMPv6 neighbor solicitations on a network interface and responds with neighbor advertisements, as described in [RFC 4861](https://tools.ietf.org/html/rfc4861) - IPv6 Neighbor Discovery Protocol.

This program is similar to [ndppd - NDP Proxy Daemon](https://github.com/DanielAdolfsson/ndppd) in "static" mode, but differs in that the source IPv6 address of neighbor advertisement is set to the same value as the target address in the neighbor solicitation.
This change enables **ndpresponder** to work in certain KVM virtual servers where NDP uses link-local addresses but *ebtables* drops outgoing packets from link-local addresses.
See my [blog post](https://yoursunny.com/t/2021/ndpresponder/) for more information.

## Installation and Usage

This program is written in Go.
It requires both a Go compiler and a C compiler.
You can compile and install this program with:

```bash
go get github.com/yoursunny/ndpresponder
```

Then you can start the program with:

```bash
sudo ndpresponder -i eth0 -n 2001:db8:3988:486e:ff2f:add3:31e3:7b00/120
```

* `-i` flag specifies the network interface name.
* `-n` flag specifies the IPv6 subnet to respond to.
  You may repeat this flag to specify multiple subnets.
  It's recommended to keep the subnet as small as possible.

You can also run this program as a Docker container:

```bash
docker run -d --name ndpresponder --network host \
  --restart always --cpus 0.02 --memory 64M \
  yoursunny/ndpresponder -i eth0 -n 2001:db8:3988:486e:ff2f:add3:31e3:7b00/120
```
