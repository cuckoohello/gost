package gost

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/go-log/log"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
)

func createDevice(cfg VPNConfig) (device device.Device, addr net.Addr, err error) {
	ip, _, err := net.ParseCIDR(cfg.Addr)

	if err != nil {
		return
	}
	addr = &net.IPAddr{IP: ip}

	device, err = tun.Open(cfg.Name, uint32(cfg.MTU))
	if err != nil {
		log.Logf("[vpn] open tun %s failed: %v", cfg.Name, err)
		return
	}

	peer := cfg.Peer
	if peer == "" {
		peer = ip.String()
	}
	cmd := fmt.Sprintf("ifconfig %s inet %s %s up",
		cfg.Name, cfg.Addr, peer)
	log.Log("[tun]", cmd)
	args := strings.Split(cmd, " ")
	if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}
	return
}
