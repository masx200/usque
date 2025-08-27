package internal

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/txthinking/socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var defaultSOCKS5Handler = new(socks5.DefaultHandle)

type socks5Server struct {
	server   *socks5.Server
	resolver *TunnelDNSResolver
	tunNet   *netstack.Net
}

func NewSOCKS5Server(address, username, password string, resolver *TunnelDNSResolver, tunNet *netstack.Net) (*socks5Server, error) {
	server, err := socks5.NewClassicServer(address, "", username, password, 0, 0)
	if err != nil {
		return nil, err
	}

	s := &socks5Server{
		server:   server,
		resolver: resolver,
		tunNet:   tunNet,
	}

	socks5.DialTCP = s.dialTCP
	socks5.DialUDP = s.dialUDP

	return s, nil
}

func (s *socks5Server) Start() error {
	return s.server.ListenAndServe(s)
}

func (s *socks5Server) dialTCP(network string, _, raddr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(raddr)
	if err != nil {
		return nil, err
	}

	ctx, ip, err := s.resolver.Resolve(context.Background(), host)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveTCPAddr(network, net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, err
	}

	return s.tunNet.DialContextTCP(ctx, addr)
}

func (s *socks5Server) dialUDP(network string, laddr, raddr string) (net.Conn, error) {
	var la *net.UDPAddr
	if laddr != "" {
		addr, err := net.ResolveUDPAddr(network, laddr)
		if err != nil {
			return nil, err
		}
		la = addr
	}

	host, port, err := net.SplitHostPort(raddr)
	if err != nil {
		return nil, err
	}

	_, ip, err := s.resolver.Resolve(context.Background(), host)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, err
	}

	rc, err := s.tunNet.DialUDP(la, addr)
	if err != nil {
		if strings.Contains(err.Error(), "port is in use") {
			// convert gvisor gonet error to net package error
			return nil, &net.AddrError{
				Err:  "address already in use",
				Addr: laddr,
			}
		}
		return nil, err
	}

	return rc, nil
}

// Modified from https://github.com/txthinking/socks5/blob/master/server.go#L263
func (*socks5Server) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdConnect {
		rc, err := r.Connect(c)
		if err != nil {
			return err
		}
		defer rc.Close()
		go func() {
			bf := make([]byte, 4*1024)
			for {
				if s.TCPTimeout != 0 {
					if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
						return
					}
				}
				i, err := rc.Read(bf)
				if err != nil {
					return
				}
				if _, err := c.Write(bf[:i]); err != nil {
					return
				}
			}
		}()
		bf := make([]byte, 4*1024)
		for {
			if s.TCPTimeout != 0 {
				if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
					return nil
				}
			}
			i, err := c.Read(bf)
			if err != nil {
				return nil
			}
			if _, err := rc.Write(bf[:i]); err != nil {
				return nil
			}
		}
	}
	if r.Cmd == socks5.CmdUDP {
		caddr, err := r.UDP(c, c.LocalAddr())
		if err != nil {
			return err
		}
		ch := make(chan byte)
		defer close(ch)
		s.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer s.AssociatedUDP.Delete(caddr.String())
		io.Copy(io.Discard, c)
		if socks5.Debug {
			log.Printf("A tcp connection that udp %#v associated closed\n", caddr.String())
		}
		return nil
	}
	return socks5.ErrUnsupportCmd
}

// Use default handler for UDP
func (*socks5Server) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	return defaultSOCKS5Handler.UDPHandle(s, addr, d)
}
