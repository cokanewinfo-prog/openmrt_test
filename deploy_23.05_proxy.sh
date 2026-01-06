#!/bin/sh
# OpenWrt 23.05 一键部署脚本
# nftables + Xray + WireGuard(wg0) + dnsmasq-full
# 国内直连，国外走 wg0
# 使用前请先备份 /etc/config/*

echo "=== Step 0: 安装必要软件包 ==="
opkg update
opkg install xray-core dnsmasq-full curl ca-bundle kmod-nft-tproxy kmod-nf-tproxy

echo "=== Step 1: 配置 WireGuard (wg0) ==="
cat <<'EOF' > /etc/config/network
config interface 'loopback'
    option ifname 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1'
    option netmask '255.0.0.0'

config interface 'lan'
    option ifname 'br-lan'
    option proto 'static'
    option ipaddr '192.168.88.200'
    option netmask '255.255.255.0'
    option ip6assign '60'

config interface 'wg0'
    option proto 'wireguard'
    option private_key '<YOUR_PRIVATE_KEY>'
    option listen_port '51820'

config wireguard_wg0
    option public_key '<PEER_PUBLIC_KEY>'
    option description 'WG_Server'
    option endpoint_host '<WG_SERVER_IP>'
    option endpoint_port '<WG_SERVER_PORT>'
    list allowed_ips '0.0.0.0/0'
    option route_allowed_ips '1'
EOF

echo "请确认 /etc/config/network 中已正确替换密钥和服务器信息"

echo "=== Step 2: 配置 dnsmasq-full ==="
cat <<'EOF' > /etc/config/dhcp
config dnsmasq
    option domainneeded '1'
    option boguspriv '1'
    option noresolv '1'
    option localise_queries '1'
    option rebind_protection '1'
    option authoritative '1'
    option readethers '1'
    option leasefile '/tmp/dhcp.leases'
    option resolvfile '/tmp/resolv.conf.auto'

    # 国内 DNS
    list server '223.5.5.5'
    list server '119.29.29.29'

    # 国外 DNS（会被 Xray 引流）
    list server '1.1.1.1'

    # 支持 ipset 域名分流
    option ipset 'proxylist'

config dhcp 'lan'
    option interface 'lan'
    option start '100'
    option limit '150'
    option leasetime '12h'
EOF

echo "=== Step 3: 更新国内 IP 集合 chnroute ==="
nft flush set inet filter chnroute 2>/dev/null
nft add set inet filter chnroute { type ipv4_addr; flags interval; } 2>/dev/null
curl -s https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest \
| grep '|CN|ipv4|' \
| awk -F\| '{print $4 "/" 32-log($5)/log(2)}' \
| while read net; do
    nft add element inet filter chnroute { $net }
done

echo "=== Step 4: 配置 nftables TPROXY 规则 ==="
mkdir -p /etc/nftables.d
cat <<'EOF' > /etc/nftables.d/99-xray.nft
table inet xray {

  set chnroute {
    type ipv4_addr
    flags interval
  }

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;

    # 回环放行
    ip daddr 127.0.0.0/8 return

    # 国内 IP 强制直连
    ip daddr @chnroute return

    # 已标记的流量跳过
    meta mark 0x1 return

    # TCP 引流到 Xray
    meta l4proto tcp meta mark set 0x1 tproxy to :12345 accept

    # UDP 引流（DNS / QUIC）
    meta l4proto udp meta mark set 0x1 tproxy to :12345 accept
  }
}
EOF

nft -f /etc/nftables.d/99-xray.nft
/etc/init.d/firewall restart

echo "=== Step 5: 配置 Xray-core ==="
mkdir -p /etc/xray
cat <<'EOF' > /etc/xray/config.json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 12345,
      "protocol": "dokodemo-door",
      "settings": {
        "network": "tcp,udp",
        "followRedirect": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http","tls"]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "wg",
      "protocol": "freedom",
      "streamSettings": {
        "sockopt": { "interface": "wg0" }
      }
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "geoip": ["cn"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "geosite": ["cn"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "outboundTag": "wg"
      }
    ]
  }
}
EOF

/etc/init.d/xray enable
/etc/init.d/xray restart

echo "=== Step 6: 配置 TPROXY 路由规则 ==="
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

# 开机自启
if ! grep -q "TPROXY_RULES" /etc/rc.local; then
    sed -i -e '/^exit 0/i\
# TPROXY_RULES\nip rule add fwmark 0x1 lookup 100\nip route add local 0.0.0.0/0 dev lo table 100' /etc/rc.local
fi

echo "=== 部署完成 ==="
echo "请确认 /etc/config/network 中 WireGuard 密钥和服务器信息已正确替换"
echo "建议重启旁路由后测试国内外流量分流"
