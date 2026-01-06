#!/bin/sh
# OpenWrt 23.05（fw4）旁路由分流一键部署脚本（无代理节点，仅 wg0 出口）
# BusyBox sh 兼容：不依赖 bash 特性；无交互；变量集中；幂等；自检/备份/回滚/日志；中文输出
# 目录结构：
#   /etc/nftables.d/99-xray-transparent.nft        (fw4 fragment，只放 set/chain)
#   /etc/dnsmasq.d/split.conf                      (dnsmasq 分流)
#   /etc/xray/conf.d/*.json + /etc/xray/config.json
#   /root/splittunnel/ (域名列表、ipset 数据、模板、README)
#
# 回滚：sh /root/deploy_splittunnel.sh --rollback
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
MARK_TPROXY="0x1"     # TPROXY 标记（进入本机 Xray）
MARK_WG="0x2"         # 走 wg0 的标记（用于 Xray 出站 sockopt.mark=2）
RT_TPROXY="100"       # policy routing table for tproxy
RT_WG="200"           # policy routing table for wg0

CN_DNS1="223.5.5.5"
CN_DNS2="119.29.29.29"
XRAY_DNS_LISTEN="127.0.0.1"
XRAY_DNS_PORT="5353"

# CN IP 列表数据源（可访问 GitHub 时使用）
CHNROUTE_URL="https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
CHNROUTE_URL2="https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"

# 路径
BASE_DIR="/root/splittunnel"
DOMAINS_DIR="$BASE_DIR/domains"
IPSET_DIR="$BASE_DIR/ipset"
TPL_DIR="$BASE_DIR/templates"
LOG_FILE="/root/deploy_splittunnel.log"
BK_BASE="/root"

# 每次 add element 最多写多少条（防止命令过长/内存压力）
CN_BATCH_SIZE="800"

########################################
# 工具函数
########################################
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"
}

die() {
  log "【错误】$*"
  log "【日志末尾】如下（最近 120 行）："
  tail -n 120 "$LOG_FILE" 2>/dev/null | sed 's/^/  /' | tee -a "$LOG_FILE"
  log "【建议排查】1) opkg 源/网络  2) wg0 是否 up  3) fw4 片段语法  4) xray -test 输出  5) 存储空间"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"
}

backup_file() {
  src="$1"
  if [ -f "$src" ]; then
    mkdir -p "$BACKUP_DIR" || true
    cp -a "$src" "$BACKUP_DIR/" || true
  fi
}

backup_dir() {
  src="$1"
  if [ -d "$src" ]; then
    mkdir -p "$BACKUP_DIR" || true
    cp -a "$src" "$BACKUP_DIR/" || true
  fi
}

########################################
# 回滚
########################################
do_rollback() {
  [ -n "${BACKUP_DIR:-}" ] && [ -d "$BACKUP_DIR" ] || die "找不到可用备份目录，无法回滚。"

  log "【回滚】开始从备份目录恢复：$BACKUP_DIR ..."

  # 恢复文件
  for f in \
    /etc/nftables.d/99-xray-transparent.nft \
    /etc/dnsmasq.d/split.conf \
    /etc/dnsmasq.d/proxy-domains.generated.conf \
    /etc/xray/config.json
  do
    b="$BACKUP_DIR/$(basename "$f")"
    [ -f "$b" ] && cp -a "$b" "$f" || true
  done

  # 恢复目录
  if [ -d "$BACKUP_DIR/conf.d" ]; then
    rm -rf /etc/xray/conf.d 2>/dev/null || true
    mkdir -p /etc/xray || true
    cp -a "$BACKUP_DIR/conf.d" /etc/xray/ || true
  fi

  # 恢复 policy routing（删除我们加的）
  ip rule del fwmark 1 lookup "$RT_TPROXY" 2>/dev/null || true
  ip route flush table "$RT_TPROXY" 2>/dev/null || true
  ip rule del fwmark 2 lookup "$RT_WG" 2>/dev/null || true
  ip route flush table "$RT_WG" 2>/dev/null || true

  # 重启服务
  fw4 reload 2>/dev/null || true
  /etc/init.d/dnsmasq restart 2>/dev/null || true
  /etc/init.d/xray restart 2>/dev/null || true

  log "【回滚】完成。"
  exit 0
}

########################################
# 参数
########################################
if [ "${1:-}" = "--rollback" ]; then
  LAST_BK="$(ls -1dt /root/backup-* 2>/dev/null | head -n 1)"
  [ -n "$LAST_BK" ] || die "未找到任何备份目录（/root/backup-*）。"
  BACKUP_DIR="$LAST_BK"
  do_rollback
fi

########################################
# 主流程开始
########################################
: > "$LOG_FILE" 2>/dev/null || true
log "=== 部署开始：旁路由分流（fw4+nftables TPROXY + Xray + dnsmasq-full，当前仅 wg0 出口）==="

need_cmd opkg
need_cmd ip
need_cmd nft
need_cmd uci
need_cmd sed
need_cmd awk
need_cmd curl
need_cmd ss
need_cmd fw4

BACKUP_DIR="$BK_BASE/backup-$(date '+%Y%m%d-%H%M%S')"
mkdir -p "$BACKUP_DIR" || die "创建备份目录失败：$BACKUP_DIR"
log "【备份】目录：$BACKUP_DIR"

log "【阶段】1/8 更新 opkg 源..."
opkg update >>"$LOG_FILE" 2>&1 || die "opkg update 失败（请检查网络/源）"

PKGS="dnsmasq-full xray-core ca-bundle curl ip-full kmod-nft-tproxy kmod-nft-socket kmod-nf-tproxy tcpdump-mini"
log "【阶段】2/8 安装依赖（如已安装会跳过）：$PKGS"
opkg install $PKGS >>"$LOG_FILE" 2>&1 || die "opkg install 失败（请检查空间/源）"

log "【阶段】3/8 检查 WireGuard 接口..."
ip link show "$WG_IFACE" >/dev/null 2>&1 || die "未找到接口：$WG_IFACE（请确认 wg0 已配置并 up）"
log "【检查】检测到 $WG_IFACE（OK）"

log "【阶段】4/8 创建目录与备份现有配置..."
mkdir -p \
  "$BASE_DIR" "$DOMAINS_DIR" "$IPSET_DIR" "$TPL_DIR" \
  /etc/nftables.d /etc/dnsmasq.d /etc/xray/conf.d \
  || die "创建目录失败"

backup_file /etc/nftables.d/99-xray-transparent.nft
backup_file /etc/dnsmasq.d/split.conf
backup_file /etc/dnsmasq.d/proxy-domains.generated.conf
backup_file /etc/xray/config.json
backup_dir /etc/xray/conf.d
log "【备份】完成。"

log "【阶段】5/8 写入配置文件（fw4 fragment / dnsmasq / xray / README / templates）..."

########################################
# 5.1 fw4 fragment：/etc/nftables.d/99-xray-transparent.nft
# 重要：这里禁止写 table 语句，fw4 会把它 include 到 table inet fw4 内
########################################
cat > /etc/nftables.d/99-xray-transparent.nft <<EOF
# fw4 fragment：会被 include 到 table inet fw4 { ... } 内部
# 禁止写 table 语句

set xray_set_cn4 { type ipv4_addr; flags interval; }
set xray_set_cn6 { type ipv6_addr; flags interval; }

set xray_set_proxy4 { type ipv4_addr; flags interval; }
set xray_set_proxy6 { type ipv6_addr; flags interval; }

set xray_set_bypass_src4 { type ipv4_addr; }
set xray_set_force_proxy_src4 { type ipv4_addr; }

chain xray_prerouting_mangle {
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

  # 设备级绕过（永不进 Xray）
  ip saddr @xray_set_bypass_src4 return

  # 【硬性要求】CN 目的 IP：在 nftables 层硬绕过，绝不进入 Xray inbound
  ip daddr @xray_set_cn4 return
  ip6 daddr @xray_set_cn6 return

  # 强制代理设备（可选，默认空集合）
  ip saddr @xray_set_force_proxy_src4 jump xray_do_tproxy

  # dnsmasq nftset 写入的代理目的集合（可选，默认空集合）
  ip daddr @xray_set_proxy4 jump xray_do_tproxy
  ip6 daddr @xray_set_proxy6 jump xray_do_tproxy

  # 兜底：非 CN 流量引流到本机 Xray
  meta l4proto { tcp, udp } jump xray_do_tproxy
  return
}

chain xray_do_tproxy {
  meta mark $MARK_TPROXY return
  meta l4proto tcp tproxy to :$XRAY_TPROXY_PORT meta mark set $MARK_TPROXY accept
  meta l4proto udp tproxy to :$XRAY_TPROXY_PORT meta mark set $MARK_TPROXY accept
  return
}
EOF

########################################
# 5.2 dnsmasq：/etc/dnsmasq.d/split.conf + generated
########################################
cat > /etc/dnsmasq.d/split.conf <<EOF
no-resolv
domain-needed
bogus-priv
cache-size=10000
log-queries=0
log-facility=/tmp/dnsmasq.log

# 默认走本机 Xray DNS（非 CN 域名会经 wg0 出国解析，避免污染/泄漏）
server=$XRAY_DNS_LISTEN#$XRAY_DNS_PORT

# 国内上游 DNS（直连）
server=$CN_DNS1
server=$CN_DNS2

# 自动维护域名列表 -> nftset（用于 L3 预分流；当前阶段可不依赖，但保留扩展点）
conf-file=/etc/dnsmasq.d/proxy-domains.generated.conf

# 国内域名：强制国内 DNS（防污染）
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
# 当前阶段无代理节点，仅 wg0 出口；此列表为后期扩展预留
openai.com
chatgpt.com
google.com
youtube.com
gstatic.com
EOF
  log "【初始化】已创建域名列表：$PROXY_DOMAINS_TXT"
fi

: > "$PROXY_DOMAINS_GEN"
awk '
  /^[[:space:]]*#/ { next }
  NF==0 { next }
  {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
    print "nftset=/" $0 "/xray_set_proxy4,xray_set_proxy6"
  }
' "$PROXY_DOMAINS_TXT" >> "$PROXY_DOMAINS_GEN"

########################################
# 5.3 Xray：conf.d + config.json（include 优先，失败会自动降级单文件）
########################################
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
    { "tag": "wg0_out", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" },
      "streamSettings": { "sockopt": { "mark": 2 } } }
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
      { "address": "https://1.1.1.1/dns-query", "skipFallback": true,
        "domains": ["geosite:geolocation-!cn"], "expectIPs": ["geoip:!cn"] },
      { "address": "$CN_DNS1", "domains": ["geosite:cn"], "expectIPs": ["geoip:cn"] }
    ]
  }
}
EOF

cat > /etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray-access.log",
    "error": "/var/log/xray-error.log"
  },
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

########################################
# 5.4 templates（后期扩展用：加入代理节点/回退）
########################################
cat > "$TPL_DIR/20-outbounds.with_proxy.json" <<'EOF'
{
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" } },
    { "tag": "wg0_out", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" },
      "streamSettings": { "sockopt": { "mark": 2 } } },

    { "tag": "proxy", "protocol": "vless", "settings": { "vnext": [ { "address": "YOUR_SERVER", "port": 443,
      "users": [ { "id": "YOUR_UUID", "encryption": "none" } ] } ] },
      "streamSettings": { "security": "tls", "tlsSettings": { "serverName": "YOUR_SNI" } } },

    { "tag": "proxy_backup", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" },
      "streamSettings": { "sockopt": { "mark": 2 } } }
  ]
}
EOF

cat > "$TPL_DIR/10-routing.with_balancer.json" <<'EOF'
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "balancers": [
      {
        "tag": "b_proxy_then_wg",
        "selector": ["proxy", "proxy_backup"],
        "strategy": {
          "type": "fallback",
          "fallbackTag": "proxy_backup",
          "ping": { "timeout": "2s", "interval": "30s", "destination": "https://www.google.com/generate_204" }
        }
      }
    ],
    "rules": [
      { "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct" },
      { "type": "field", "ip": ["geoip:cn", "geoip:private"], "outboundTag": "direct" },
      { "type": "field", "domain": ["geosite:geolocation-!cn"], "balancerTag": "b_proxy_then_wg" },
      { "type": "field", "inboundTag": ["tproxy_in"], "balancerTag": "b_proxy_then_wg" }
    ]
  }
}
EOF

########################################
# 5.5 README
########################################
cat > "$BASE_DIR/README.md" <<EOF
# splittunnel（OpenWrt 23.05 / fw4 / nftables + Xray）

## 当前模式（上线版）
- 无代理节点，仅 wg0 出口
- CN 流量在 nftables 层硬绕过，绝不进入 Xray inbound
- 非 CN 流量通过 TPROXY 进入 Xray，默认走 wg0_out（sockopt.mark=2 + ip rule table 200）

## 关键文件
- /etc/nftables.d/99-xray-transparent.nft（fw4 fragment：声明集合/链）
- /root/splittunnel/ipset/cn4.nft（CN 集合灌入：脚本在 fw4 reload 后执行 nft -f）
- /etc/dnsmasq.d/split.conf（dns 分流）
- /etc/xray/conf.d/*.json + /etc/xray/config.json（xray）

## 后期扩展
- templates/20-outbounds.with_proxy.json：加入 proxy 节点
- templates/10-routing.with_balancer.json：加入 fallback（proxy 优先、wg0 兜底）
EOF

log "【阶段】6/8 生成 CN IPv4 集合（cn4.txt / cn4.nft，写入 table inet fw4 xray_set_cn4）..."

CN_TXT="$IPSET_DIR/cn4.txt"
CN_NFT="$IPSET_DIR/cn4.nft"

fetch_ok=0
if curl -fsSL "$CHNROUTE_URL" -o "$CN_TXT" >>"$LOG_FILE" 2>&1; then
  fetch_ok=1
else
  log "【提示】主数据源失败，尝试备用数据源..."
  if curl -fsSL "$CHNROUTE_URL2" -o "$CN_TXT" >>"$LOG_FILE" 2>&1; then
    fetch_ok=1
  fi
fi
[ "$fetch_ok" -eq 1 ] || die "CN IPv4 列表下载失败（请检查网络是否能访问 GitHub）"

# 生成 cn4.nft（分批 add element，避免命令过长）
# 仅保留 IPv4/CIDR 行
TMP_IPS="/tmp/cn4.ips.$$"
awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ { print $0 }' "$CN_TXT" > "$TMP_IPS" || true
[ -s "$TMP_IPS" ] || die "CN IPv4 列表为空（下载内容异常）"

{
  echo "flush set inet fw4 xray_set_cn4"
} > "$CN_NFT"

i=0
batch=""
while IFS= read -r cidr; do
  [ -n "$cidr" ] || continue
  if [ $i -eq 0 ]; then
    batch="$cidr"
  else
    batch="$batch, $cidr"
  fi
  i=$((i + 1))
  if [ $i -ge "$CN_BATCH_SIZE" ]; then
    echo "add element inet fw4 xray_set_cn4 { $batch }" >> "$CN_NFT"
    i=0
    batch=""
  fi
done < "$TMP_IPS"

if [ $i -gt 0 ] && [ -n "$batch" ]; then
  echo "add element inet fw4 xray_set_cn4 { $batch }" >> "$CN_NFT"
fi

rm -f "$TMP_IPS" 2>/dev/null || true
log "【生成】cn4.nft 已生成：$CN_NFT"

log "【阶段】7/8 配置 dnsmasq 加载 confdir + 配置 policy routing（幂等）..."

# dnsmasq 加载 /etc/dnsmasq.d（不交互）
uci -q set dhcp.@dnsmasq[0].confdir="/etc/dnsmasq.d"
uci -q commit dhcp

# policy routing for tproxy
ip rule del fwmark 1 lookup "$RT_TPROXY" 2>/dev/null || true
ip rule add fwmark 1 lookup "$RT_TPROXY" 2>/dev/null || true
ip route flush table "$RT_TPROXY" 2>/dev/null || true
ip route add local 0.0.0.0/0 dev lo table "$RT_TPROXY" 2>/dev/null || true

# policy routing for wg0 marked traffic (from Xray outbounds sockopt.mark=2)
ip rule del fwmark 2 lookup "$RT_WG" 2>/dev/null || true
ip rule add fwmark 2 lookup "$RT_WG" 2>/dev/null || true
ip route flush table "$RT_WG" 2>/dev/null || true
ip route add default dev "$WG_IFACE" table "$RT_WG" 2>/dev/null || true

log "【阶段】8/8 校验并加载（fw4 + cn4 + xray + dnsmasq），然后重启服务..."

# 1) fw4 规则语法校验（必须基于完整上下文）
log "【校验】nftables 语法检查（fw4 print | nft -c）"
fw4 print >/tmp/fw4.ruleset.nft 2>>"$LOG_FILE" || die "fw4 print 失败"
nft -c -f /tmp/fw4.ruleset.nft >>"$LOG_FILE" 2>&1 || die "nftables 语法检查失败（fw4 ruleset 校验未通过）"

# 2) 应用 fw4 规则
log "【加载】应用防火墙规则（fw4 reload）"
fw4 reload >>"$LOG_FILE" 2>&1 || die "fw4 reload 失败（请检查 /etc/nftables.d 片段语法）"

# 3) 灌入 CN 集合（必须在 fw4 reload 后）
log "【加载】灌入 CN IPv4 集合（nft -f cn4.nft）"
nft -f "$CN_NFT" >>"$LOG_FILE" 2>&1 || die "CN 集合写入失败（请检查 xray_set_cn4 是否已声明）"

# 4) 校验 Xray 配置：include 不兼容自动降级单文件
log "【校验】Xray 配置检查（include 优先，失败自动降级单文件）"
XRAY_OK=0
if command -v xray >/dev/null 2>&1; then
  if xray run -test -config /etc/xray/config.json >>"$LOG_FILE" 2>&1; then
    log "【校验】Xray include 模式通过（使用 conf.d 结构）"
    XRAY_OK=1
  else
    log "【提示】include 不兼容：自动生成等价单文件 config.json"
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
    { "tag": "wg0_out", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" },
      "streamSettings": { "sockopt": { "mark": 2 } } }
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
      { "address": "https://1.1.1.1/dns-query", "skipFallback": true,
        "domains": ["geosite:geolocation-!cn"], "expectIPs": ["geoip:!cn"] },
      { "address": "$CN_DNS1", "domains": ["geosite:cn"], "expectIPs": ["geoip:cn"] }
    ]
  }
}
EOF
    xray run -test -config /etc/xray/config.json >>"$LOG_FILE" 2>&1 && XRAY_OK=1
  fi
fi
[ "$XRAY_OK" -eq 1 ] || die "Xray 配置校验失败（请查看 /var/log/xray-error.log 与日志）"

# 5) 重启服务
log "【重启】dnsmasq / xray"
 /etc/init.d/dnsmasq restart >>"$LOG_FILE" 2>&1 || die "dnsmasq 重启失败"
 /etc/init.d/xray enable >>"$LOG_FILE" 2>&1 || true
 /etc/init.d/xray restart >>"$LOG_FILE" 2>&1 || die "xray 重启失败"

########################################
# 中文自检摘要
########################################
log "=== 部署完成：中文自检摘要 ==="

# wg0
if ip link show "$WG_IFACE" >/dev/null 2>&1; then
  log "【自检】wg0：存在（OK）"
else
  log "【自检】wg0：不存在（异常）"
fi

# fw4 fragment 链
if nft list chain inet fw4 xray_prerouting_mangle >/dev/null 2>&1; then
  log "【自检】nftables：xray_prerouting_mangle 链存在（OK）"
else
  log "【自检】nftables：xray_prerouting_mangle 链不存在（异常）"
fi

# CN 集合数量
CN_COUNT="$(nft list set inet fw4 xray_set_cn4 2>/dev/null | grep -c '/' 2>/dev/null)"
if [ "${CN_COUNT:-0}" -gt 0 ]; then
  log "【自检】CN 集合：元素数量 > 0（OK，约 ${CN_COUNT} 行）"
else
  log "【自检】CN 集合：为空（异常）"
fi

# Xray 端口监听
if ss -lunpt 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT"; then
  log "【自检】Xray：TPROXY 端口 $XRAY_TPROXY_PORT 在监听（OK）"
else
  log "【自检】Xray：TPROXY 端口 $XRAY_TPROXY_PORT 未监听（异常）"
fi

# dnsmasq 53
if ss -lunpt 2>/dev/null | grep -q ":53"; then
  log "【自检】dnsmasq：53 端口在监听（OK）"
else
  log "【自检】dnsmasq：53 端口未监听（异常）"
fi

# dnsmasq confdir
CONF_DIR="$(uci -q get dhcp.@dnsmasq[0].confdir 2>/dev/null)"
if [ "$CONF_DIR" = "/etc/dnsmasq.d" ]; then
  log "【自检】dnsmasq：confdir=/etc/dnsmasq.d（OK）"
else
  log "【自检】dnsmasq：confdir 未正确设置（异常）"
fi

# 验收标准提示（不自动抓包，只提示命令）
log "=== 强制验收提示 ==="
log "【验收1】确认 CN 硬绕过在 tproxy 之前：nft list chain inet fw4 xray_prerouting_mangle"
log "【验收2】抓包证明 CN 不进 TPROXY 端口：tcpdump -ni any port $XRAY_TPROXY_PORT"
log "【提示】客户端需将“默认网关”和“DNS”指向：$SIDECAR_IP"
log "【提示】回滚命令：sh /root/deploy_splittunnel.sh --rollback"
log "=== 结束 ==="
exit 0
