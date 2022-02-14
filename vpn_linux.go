package gost

import (
	"fmt"
	"net"

	"github.com/go-log/log"
	"github.com/milosgajdos/tenus"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
)

func createDevice(cfg VPNConfig) (device device.Device, addr net.Addr, err error) {
	ip, ipNet, err := net.ParseCIDR(cfg.Addr)

	if err != nil {
		return
	}
	addr = &net.IPAddr{IP: ip}

	device, err = tun.Open(cfg.Name, uint32(cfg.MTU))
	if err != nil {
		log.Logf("[vpn] open tun %s failed: %v", cfg.Name, err)
		return
	}

	link, err := tenus.NewLinkFrom(cfg.Name)
	if err != nil {
		return
	}

	cmd := fmt.Sprintf("ip address add %s dev %s", cfg.Addr, cfg.Name)
	log.Log("[tun]", cmd)
	if er := link.SetLinkIp(ip, ipNet); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	cmd = fmt.Sprintf("ip link set dev %s up", cfg.Name)
	log.Log("[tun]", cmd)
	if er := link.SetLinkUp(); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}
	return
}
