#!/bin/sh
# OpenWrt BusyBox sh 兼容、非交互、幂等部署脚本（无代理节点，仅 wg0 出口）
# 特性：自动备份/回滚、中文输出、中文自检摘要、Xray include 不兼容时自动降级单文件
# 日志：/root/deploy_splittunnel.log

set -u

########################################
# 变量区（只改这里）
########################################
LAN_SUBNET="192.168.88.0/24"
MAIN_ROUTER_IP="192.168.88.1"
SIDECAR_IP="192.168.88.200"
WG_IFACE="wg0"

XRAY_TPROXY_PORT="12345"

MARK_TPROXY="0x1"
MARK_WG="0x2"
RT_TPROXY="100"
RT_WG="200"

CN_DNS1="223.5.5.5"
CN_DNS2="119.29.29.29"
XRAY_DNS_LISTEN="127.0.0.1"
XRAY_DNS_PORT="5353"

CHNROUTE_URL="https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
CHNROUTE_URL2="https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"

BASE_DIR="/root/splittunnel"
DOMAINS_DIR="$BASE_DIR/domains"
IPSET_DIR="$BASE_DIR/ipset"
BK_BASE="/root"
LOG_FILE="/root/deploy_splittunnel.log"

########################################
# 工具函数
########################################
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
die() {
  log "【错误】$*"
  log "【建议排查】网络连通性 / opkg 源 / 存储空间 / wg0 状态 / nftables 模块 / xray 配置"
  log "【日志位置】$LOG_FILE"
  exit 1
}
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"; }
backup_file() { [ -f "$1" ] && { mkdir -p "$BACKUP_DIR" || true; cp -a "$1" "$BACKUP_DIR/" || true; }; }
backup_dir() { [ -d "$1" ] && { mkdir -p "$BACKUP_DIR" || true; cp -a "$1" "$BACKUP_DIR/" || true; }; }

########################################
# 回滚
########################################
do_rollback() {
  [ -n "${BACKUP_DIR:-}" ] && [ -d "$BACKUP_DIR" ] || die "找不到可用备份目录，无法回滚。"
  log "【回滚】开始从备份目录恢复：$BACKUP_DIR ..."

  for f in \
    /etc/nftables.d/99-xray-transparent.nft \
    /etc/dnsmasq.d/split.conf \
    /etc/dnsmasq.d/proxy-domains.generated.conf \
    /etc/xray/config.json
  do
    if [ -f "$BACKUP_DIR/$(basename "$f")" ]; then
      cp -a "$BACKUP_DIR/$(basename "$f")" "$f" || true
    fi
  done

  if [ -d "$BACKUP_DIR/conf.d" ]; then
    rm -rf /etc/xray/conf.d 2>/dev/null || true
    cp -a "$BACKUP_DIR/conf.d" /etc/xray/ || true
  fi

  ip rule del fwmark 1 lookup "$RT_TPROXY" 2>/dev/null || true
  ip route flush table "$RT_TPROXY" 2>/dev/null || true
  ip rule del fwmark 2 lookup "$RT_WG" 2>/dev/null || true
  ip route flush table "$RT_WG" 2>/dev/null || true

  /etc/init.d/firewall restart 2>/dev/null || true
  /etc/init.d/dnsmasq restart 2>/dev/null || true
  /etc/init.d/xray restart 2>/dev/null || true

  log "【回滚】完成。"
  exit 0
}

if [ "${1:-}" = "--rollback" ]; then
  LAST_BK="$(ls -1dt /root/backup-* 2>/dev/null | head -n 1)"
  [ -n "$LAST_BK" ] || die "未找到任何备份目录（/root/backup-*）。"
  BACKUP_DIR="$LAST_BK"
  do_rollback
fi

########################################
# 主流程
########################################
: > "$LOG_FILE" 2>/dev/null || true
log "=== 部署开始：旁路由分流（无代理节点，仅 wg0 出口）==="

need_cmd opkg
need_cmd ip
need_cmd nft
need_cmd uci
need_cmd sed
need_cmd awk
need_cmd curl
need_cmd ss

BACKUP_DIR="$BK_BASE/backup-$(date '+%Y%m%d-%H%M%S')"
mkdir -p "$BACKUP_DIR" || die "创建备份目录失败：$BACKUP_DIR"
log "【备份】目录：$BACKUP_DIR"

log "【阶段】1/7 更新 opkg 源..."
opkg update >>"$LOG_FILE" 2>&1 || die "opkg update 失败"

PKGS="dnsmasq-full xray-core ca-bundle curl ip-full kmod-nft-tproxy kmod-nft-socket kmod-nf-tproxy"
log "【阶段】2/7 安装依赖（如已安装会跳过）：$PKGS"
opkg install $PKGS >>"$LOG_FILE" 2>&1 || die "opkg install 失败"

log "【阶段】3/7 检查 WireGuard 接口..."
ip link show "$WG_IFACE" >/dev/null 2>&1 || die "未找到接口：$WG_IFACE（请确认 wg0 已配置并 up）"
log "【检查】检测到 $WG_IFACE（OK）"

log "【阶段】4/7 准备目录与备份现有配置..."
mkdir -p "$BASE_DIR" "$DOMAINS_DIR" "$IPSET_DIR" /etc/nftables.d /etc/dnsmasq.d /etc/xray/conf.d || die "创建目录失败"

backup_file /etc/nftables.d/99-xray-transparent.nft
backup_file /etc/dnsmasq.d/split.conf
backup_file /etc/dnsmasq.d/proxy-domains.generated.conf
backup_file /etc/xray/config.json
backup_dir /etc/xray/conf.d
log "【备份】完成。"

log "【阶段】5/7 写入配置文件（nftables / dnsmasq / xray）..."

# nftables：CN 硬绕过 + 非 CN tproxy
cat > /etc/nftables.d/99-xray-transparent.nft <<EOF
#!/usr/sbin/nft -f

table inet xray_tproxy {

  # =========================
  # 集合定义
  # =========================
  set set_cn4 { type ipv4_addr; flags interval; }
  set set_cn6 { type ipv6_addr; flags interval; }

  set set_proxy4 { type ipv4_addr; flags interval; }
  set set_proxy6 { type ipv6_addr; flags interval; }

  set set_bypass_src4 { type ipv4_addr; }
  set set_force_wg_src4 { type ipv4_addr; }
  set set_force_proxy_src4 { type ipv4_addr; }

  # =========================
  # 主链：PREROUTING / mangle
  # =========================
  chain prerouting_mangle {
    type filter hook prerouting priority mangle; policy accept;

    ct state established,related accept

    iifname "lo" accept
    ip daddr 127.0.0.0/8 accept
    ip daddr 224.0.0.0/4 accept
    ip daddr 255.255.255.255 accept
    ip daddr 192.168.0.0/16 accept
    ip daddr 10.0.0.0/8 accept
    ip daddr 172.16.0.0/12 accept

    ip6 daddr ::1 accept
    ip6 daddr fe80::/10 accept
    ip6 daddr fc00::/7 accept
    ip6 daddr ff00::/8 accept

    # 设备级绕过
    ip saddr @set_bypass_src4 return

    # 【硬性要求】CN 目的 IP 直接放行，绝不进入 Xray
    ip daddr @set_cn4 return
    ip6 daddr @set_cn6 return

    # 强制代理设备
    ip saddr @set_force_proxy_src4 jump do_tproxy

    # dnsmasq 命中的代理目的 IP
    ip daddr @set_proxy4 jump do_tproxy
    ip6 daddr @set_proxy6 jump do_tproxy

    # 兜底：非 CN 流量
    meta l4proto { tcp, udp } jump do_tproxy
    return
  }

  # =========================
  # 子链：TPROXY 处理
  # =========================
  chain do_tproxy {

    # 防止重复处理
    meta mark 0x1 return

    meta l4proto tcp tproxy to :12345 meta mark set 0x1 accept
    meta l4proto udp tproxy to :12345 meta mark set 0x1 accept
    return
  }
}
EOF

# dnsmasq：CN 直连上游；其余走本机 Xray DNS；nftset 仍保留（便于后期扩展域名列表）
cat > /etc/dnsmasq.d/split.conf <<EOF
no-resolv
domain-needed
bogus-priv
server=$XRAY_DNS_LISTEN#$XRAY_DNS_PORT
cache-size=10000
log-queries=0
log-facility=/tmp/dnsmasq.log

server=$CN_DNS1
server=$CN_DNS2

# 可维护域名列表：解析结果写入 nftset（后期扩展更舒服）
conf-file=/etc/dnsmasq.d/proxy-domains.generated.conf

server=/cn/$CN_DNS1
server=/cn/$CN_DNS2
server=/qq.com/$CN_DNS2
server=/taobao.com/$CN_DNS1
server=/jd.com/$CN_DNS1
server=/bilibili.com/$CN_DNS1
server=/zhihu.com/$CN_DNS1
EOF

PROXY_DOMAINS_TXT="$DOMAINS_DIR/proxy_domains.txt"
PROXY_DOMAINS_GEN="/etc/dnsmasq.d/proxy-domains.generated.conf"
if [ ! -f "$PROXY_DOMAINS_TXT" ]; then
  cat > "$PROXY_DOMAINS_TXT" <<EOF
# 每行一个域名（不要以点开头），# 开头为注释
openai.com
chatgpt.com
google.com
youtube.com
gstatic.com
EOF
  log "【初始化】已创建默认域名列表：$PROXY_DOMAINS_TXT"
fi
: > "$PROXY_DOMAINS_GEN"
awk '
  /^[[:space:]]*#/ { next }
  NF==0 { next }
  {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
    print "nftset=/" $0 "/set_proxy4,set_proxy6"
  }
' "$PROXY_DOMAINS_TXT" >> "$PROXY_DOMAINS_GEN"

# Xray conf.d（维护结构保留）
cat > /etc/xray/conf.d/00-inbounds.json <<EOF
{
  "inbounds": [
    {
      "tag": "tproxy_in",
      "listen": "0.0.0.0",
      "port": $XRAY_TPROXY_PORT,
      "protocol": "dokodemo-door",
      "settings": { "network": "tcp,udp", "followRedirect": true },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": false }
    }
  ]
}
EOF

cat > /etc/xray/conf.d/20-outbounds.json <<EOF
{
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" } },
    { "tag": "wg0_out", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" }, "streamSettings": { "sockopt": { "mark": 2 } } }
  ]
}
EOF

cat > /etc/xray/conf.d/10-routing.json <<EOF
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct" },
      { "type": "field", "ip": ["geoip:cn", "geoip:private"], "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["tproxy_in"], "outboundTag": "wg0_out" }
    ]
  }
}
EOF

cat > /etc/xray/conf.d/30-dns.json <<EOF
{
  "dns": {
    "tag": "xray_dns",
    "queryStrategy": "UseIP",
    "servers": [
      { "address": "https://1.1.1.1/dns-query", "skipFallback": true, "domains": ["geosite:geolocation-!cn"], "expectIPs": ["geoip:!cn"] },
      { "address": "$CN_DNS1", "domains": ["geosite:cn"], "expectIPs": ["geoip:cn"] }
    ]
  }
}
EOF

cat > /etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning", "access": "/var/log/xray-access.log", "error": "/var/log/xray-error.log" },
  "inbounds": [],
  "outbounds": [],
  "routing": {},
  "dns": {},
  "include": [
    "/etc/xray/conf.d/00-inbounds.json",
    "/etc/xray/conf.d/10-routing.json",
    "/etc/xray/conf.d/20-outbounds.json",
    "/etc/xray/conf.d/30-dns.json"
  ]
}
EOF

log "【阶段】6/7 生成大陆 IP 集合并写入 nft set..."
CN_TXT="$IPSET_DIR/cn4.txt"
CN_NFT="$IPSET_DIR/cn4.nft"
fetch_ok=0
if curl -fsSL "$CHNROUTE_URL" -o "$CN_TXT" >>"$LOG_FILE" 2>&1; then fetch_ok=1; else
  log "【提示】主数据源失败，尝试备用数据源..."
  if curl -fsSL "$CHNROUTE_URL2" -o "$CN_TXT" >>"$LOG_FILE" 2>&1; then fetch_ok=1; fi
fi
[ "$fetch_ok" -eq 1 ] || die "大陆路由列表下载失败（请检查是否能访问 GitHub）"

{
  echo "flush set inet xray_tproxy set_cn4"
  echo -n "add element inet xray_tproxy set_cn4 { "
  awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ { printf "%s, ", $0 }' "$CN_TXT" | sed 's/, $//'
  echo " }"
} > "$CN_NFT"

log "【配置】dnsmasq 加载 /etc/dnsmasq.d（非交互）"
uci -q set dhcp.@dnsmasq[0].confdir="/etc/dnsmasq.d"
uci -q commit dhcp

log "【配置】策略路由（幂等）"
ip rule del fwmark 1 lookup "$RT_TPROXY" 2>/dev/null || true
ip rule add fwmark 1 lookup "$RT_TPROXY" 2>/dev/null || true
ip route flush table "$RT_TPROXY" 2>/dev/null || true
ip route add local 0.0.0.0/0 dev lo table "$RT_TPROXY" 2>/dev/null || true

ip rule del fwmark 2 lookup "$RT_WG" 2>/dev/null || true
ip rule add fwmark 2 lookup "$RT_WG" 2>/dev/null || true
ip route flush table "$RT_WG" 2>/dev/null || true
ip route add default dev "$WG_IFACE" table "$RT_WG" 2>/dev/null || true

log "【校验】nftables 语法检查"
nft -c -f /etc/nftables.d/99-xray-transparent.nft >>"$LOG_FILE" 2>&1 || die "nftables 语法检查失败"

log "【加载】应用 nftables 规则与 CN 集合"
nft -f /etc/nftables.d/99-xray-transparent.nft >>"$LOG_FILE" 2>&1 || die "加载 nftables 规则失败"
nft -f "$CN_NFT" >>"$LOG_FILE" 2>&1 || die "写入 CN 集合失败"

log "【校验】Xray 配置检查（include 优先，失败自动降级单文件）"
XRAY_OK=0
if command -v xray >/dev/null 2>&1; then
  if xray run -test -config /etc/xray/config.json >>"$LOG_FILE" 2>&1; then
    log "【校验】include 模式通过（使用 conf.d 结构）"
    XRAY_OK=1
  else
    log "【提示】include 不兼容：自动切换为单文件 config.json（上线兼容模式）"
    cat > /etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning", "access": "/var/log/xray-access.log", "error": "/var/log/xray-error.log" },
  "inbounds": [
    {
      "tag": "tproxy_in",
      "listen": "0.0.0.0",
      "port": $XRAY_TPROXY_PORT,
      "protocol": "dokodemo-door",
      "settings": { "network": "tcp,udp", "followRedirect": true },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": false }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" } },
    { "tag": "wg0_out", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" }, "streamSettings": { "sockopt": { "mark": 2 } } }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct" },
      { "type": "field", "ip": ["geoip:cn", "geoip:private"], "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["tproxy_in"], "outboundTag": "wg0_out" }
    ]
  },
  "dns": {
    "tag": "xray_dns",
    "queryStrategy": "UseIP",
    "servers": [
      { "address": "https://1.1.1.1/dns-query", "skipFallback": true, "domains": ["geosite:geolocation-!cn"], "expectIPs": ["geoip:!cn"] },
      { "address": "$CN_DNS1", "domains": ["geosite:cn"], "expectIPs": ["geoip:cn"] }
    ]
  }
}
EOF
    xray run -test -config /etc/xray/config.json >>"$LOG_FILE" 2>&1 && XRAY_OK=1
  fi
fi
[ "$XRAY_OK" -eq 1 ] || die "Xray 配置校验失败"

log "【阶段】7/7 重启服务..."
/etc/init.d/network reload >>"$LOG_FILE" 2>&1 || true
/etc/init.d/firewall restart >>"$LOG_FILE" 2>&1 || die "firewall 重启失败"
 /etc/init.d/dnsmasq restart >>"$LOG_FILE" 2>&1 || die "dnsmasq 重启失败"
 /etc/init.d/xray enable >>"$LOG_FILE" 2>&1 || true
 /etc/init.d/xray restart >>"$LOG_FILE" 2>&1 || die "xray 重启失败"

log "=== 部署完成：中文自检摘要 ==="

if ip link show "$WG_IFACE" >/dev/null 2>&1; then log "【自检】wg0：存在（OK）"; else log "【自检】wg0：不存在（异常）"; fi
if nft list table inet xray_tproxy >/dev/null 2>&1; then log "【自检】nftables：xray_tproxy 表已加载（OK）"; else log "【自检】nftables：xray_tproxy 表未加载（异常）"; fi

CN_COUNT="$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -c '/' 2>/dev/null)"
if [ "${CN_COUNT:-0}" -gt 0 ]; then
  log "【自检】CN 集合：元素数量 > 0（OK，约 ${CN_COUNT} 行）"
else
  log "【自检】CN 集合：为空（异常）"
fi

if ss -lunpt 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT"; then log "【自检】Xray：TPROXY 端口 $XRAY_TPROXY_PORT 在监听（OK）"; else log "【自检】Xray：TPROXY 端口 $XRAY_TPROXY_PORT 未监听（异常）"; fi
if ss -lunpt 2>/dev/null | grep -q ":53"; then log "【自检】dnsmasq：53 端口在监听（OK）"; else log "【自检】dnsmasq：53 端口未监听（异常）"; fi

CONF_DIR="$(uci -q get dhcp.@dnsmasq[0].confdir 2>/dev/null)"
if [ "$CONF_DIR" = "/etc/dnsmasq.d" ]; then log "【自检】dnsmasq：confdir=/etc/dnsmasq.d（OK）"; else log "【自检】dnsmasq：confdir 未正确设置（异常）"; fi

log "【提示】客户端需将“默认网关”和“DNS”指向：$SIDECAR_IP"
log "【提示】回滚命令：sh /root/deploy_splittunnel.sh --rollback"
log "=== 结束 ==="
exit 0
