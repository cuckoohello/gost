module github.com/ginuerzh/gost

go 1.17

require (
	git.torproject.org/pluggable-transports/goptlib.git v1.2.0
	github.com/LiamHaworth/go-tproxy v0.0.0-20190726054950-ef7efd7f24ed
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d
	github.com/docker/libcontainer v2.2.1+incompatible
	github.com/go-gost/gosocks4 v0.0.1
	github.com/go-gost/gosocks5 v0.3.0
	github.com/go-gost/relay v0.1.1-0.20211123134818-8ef7fd81ffd7
	github.com/go-gost/tls-dissector v0.0.2-0.20211125135007-2b5d5bd9c07e
	github.com/go-log/log v0.2.0
	github.com/gobwas/glob v0.2.3
	github.com/gorilla/websocket v1.4.2
	github.com/klauspost/compress v1.13.6
	github.com/lucas-clemente/quic-go v0.24.0
	github.com/miekg/dns v1.1.43
	github.com/milosgajdos/tenus v0.0.3
	github.com/ryanuber/go-glob v1.0.0
	github.com/shadowsocks/go-shadowsocks2 v0.1.5
	github.com/shadowsocks/shadowsocks-go v0.0.0-20200409064450-3e585ff90601
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/xjasonlyu/tun2socks/v2 v2.0.0-00010101000000-000000000000
	github.com/xtaci/kcp-go v5.4.20+incompatible
	github.com/xtaci/smux v1.5.16
	github.com/xtaci/tcpraw v1.2.25
	gitlab.com/yawning/obfs4.git v0.0.0-20210511220700-e330d1b7024b
	golang.org/x/crypto v0.0.0-20220131195533-30dcbda58838
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

require (
	github.com/Dreamacro/go-shadowsocks2 v0.1.7 // indirect
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/cheekybits/genny v1.0.0 // indirect
	github.com/coreos/go-iptables v0.6.0 // indirect
	github.com/dchest/siphash v1.2.2 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/klauspost/reedsolomon v1.9.15 // indirect
	github.com/marten-seemann/qtls-go1-16 v0.1.4 // indirect
	github.com/marten-seemann/qtls-go1-17 v0.1.0 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/templexxx/cpufeat v0.0.0-20180724012125-cef66df7f161 // indirect
	github.com/templexxx/xor v0.0.0-20191217153810-f85b25db303b // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/xtaci/lossyconn v0.0.0-20200209145036-adba10fffc37 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/sys v0.0.0-20220204135822-1c1b9b1eba6a // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20211116232009-f0f3c7e86c11 // indirect
	golang.org/x/tools v0.1.9 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20220202223031-3b95c81cc178 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gvisor.dev/gvisor v0.0.0-20220208035940-56a131734b85 // indirect
)

replace github.com/xjasonlyu/tun2socks/v2 => github.com/cuckoohello/tun2socks/v2 v2.3.3
