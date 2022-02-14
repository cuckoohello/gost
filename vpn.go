package gost

import (
	"net"
	"sync"

	"github.com/go-log/log"
	"github.com/xjasonlyu/tun2socks/v2/component/dialer"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/stack"
)

// VPNConfig is the config for TUN device.
type VPNConfig struct {
	Name      string
	Addr      string
	Peer      string // peer addr of point-to-point on MacOS
	MTU       int
	FwMark    int
	Interface string
}

type vpnListener struct {
	addr     net.Addr
	tcpQueue chan adapter.TCPConn
	udpQueue chan adapter.UDPConn
	config   VPNConfig
	stack    *stack.Stack
	device   device.Device
}

func VpnListener(cfg VPNConfig) (Listener, error) {
	if cfg.FwMark != 0 {
		dialer.SetMark(cfg.FwMark)
	}
	if cfg.Interface != "" {
		if err := dialer.BindToInterface(cfg.Interface); err != nil {
			log.Logf("[vpn] bind to interface %s failed: %v", cfg.Interface, err)
			return nil, err
		}
	}

	device, addr, err := createDevice(cfg)
	if err != nil {
		return nil, err
	}

	ln := &vpnListener{
		addr:     addr,
		tcpQueue: make(chan adapter.TCPConn),
		udpQueue: make(chan adapter.UDPConn),
		config:   cfg,
		device:   device,
	}

	err = ln.setStack()
	return ln, err
}

func (l *vpnListener) setStack() (err error) {
	defer func() {
		if err == nil {
			log.Logf("[vpn] tun %s://%s success", l.device.Type(), l.device.Name())
		}
	}()

	l.stack, err = stack.New(l.device, l, stack.WithDefault())
	return
}

func (l *vpnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.tcpQueue:
		return conn, nil
	case conn := <-l.udpQueue:
		return conn, nil
	}
}

func (l *vpnListener) Addr() net.Addr {
	return l.addr
}

func (l *vpnListener) Close() error {
	if l.device != nil {
		return l.device.Close()
	}
	return nil
}

func (l *vpnListener) HandleTCPConn(conn adapter.TCPConn) {
	l.tcpQueue <- conn
}

func (l *vpnListener) HandleUDPConn(conn adapter.UDPConn) {
	l.udpQueue <- conn
}

type vpnHandler struct {
	options *HandlerOptions
	routes  sync.Map
	chExit  chan struct{}
}

func (h *vpnHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *vpnHandler) Handle(conn net.Conn) {

	if tcpConn, ok := conn.(adapter.TCPConn); ok {
		h.HandleTCPConn(tcpConn)
	} else if udpConn, ok := conn.(adapter.UDPConn); ok {
		h.HandleUDPConn(udpConn)
	}
}

func (h *vpnHandler) HandleTCPConn(conn adapter.TCPConn) {
}

func (h *vpnHandler) HandleUDPConn(conn adapter.UDPConn) {
}
