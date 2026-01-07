#!/bin/sh

###############################################################################
# OpenWrt 23.05 旁路由分流一键部署（nftables + Xray-core + wg0 + dnsmasq-full）
# 工程交付：可直接部署上线（当前无代理节点）
#
# 关键修复：
# 1) nftables 规则文件不再使用 nft 的 define 宏（避免解析成 hostname / mark 失败）
# 2) nft set 不再写 elements = { } 空集合（避免 “unexpected }”）
# 3) CN4 nft set 生成逻辑改为无尾逗号、自动过滤脏行、去除 CRLF（避免 nft 解析失败）
###############################################################################

#========================
# 变量块（集中配置，禁止交互）
#========================
LAN_SUBNET="192.168.88.0/24"
MAIN_ROUTER_IP="192.168.88.1"
SIDECAR_IP="192.168.88.200"
WG_IFACE="wg0"

TPROXY_PORT="12345"
XRAY_DNS_PORT="5353"

MARK_TPROXY_HEX="0x1"
MARK_WG_HEX="0x2"
TABLE_TPROXY="100"
TABLE_WG="200"

# 下载源（可按企业内网镜像替换）
CN4_URL="https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"
GEOIP_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
GEOSITE_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
CN_DOMAINS_URL="https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"

DOMESTIC_DNS1="223.5.5.5"
DOMESTIC_DNS2="119.29.29.29"
FOREIGN_DNS1="1.1.1.1"
FOREIGN_DNS2="8.8.8.8"

LOG_FILE="/root/deploy_splittunnel.log"

#========================
# 工具函数
#========================
ts() { date "+%Y-%m-%d %H:%M:%S"; }

log() {
  echo "$(ts) $*" | tee -a "$LOG_FILE"
}

run() {
  log "执行：$*"
  sh -c "$*" >>"$LOG_FILE" 2>&1
  rc=$?
  if [ $rc -ne 0 ]; then
    log "错误：命令执行失败（返回码 $rc）：$*"
    return $rc
  fi
  return 0
}

exists_cmd() {
  command -v "$1" >/dev/null 2>&1
}

#========================
# 备份与回滚
#========================
BACKUP_DIR=""
ROLLBACK_ONLY="0"

make_backup_dir() {
  BACKUP_DIR="/root/backup-$(date +%Y%m%d-%H%M%S)"
  run "mkdir -p '$BACKUP_DIR'" || return 1
  echo "$BACKUP_DIR" > /root/splittunnel.last_backup 2>/dev/null
  return 0
}

backup_path() {
  p="$1"
  if [ -e "$p" ]; then
    d="$(dirname "$p")"
    run "mkdir -p '$BACKUP_DIR$d'" || return 1
    run "cp -a '$p' '$BACKUP_DIR$p'" || return 1
  fi
  return 0
}

rollback_from_dir() {
  dir="$1"
  if [ ! -d "$dir" ]; then
    log "回滚失败：备份目录不存在：$dir"
    return 1
  fi

  log "开始回滚：从备份目录恢复：$dir"
  for p in \
    /etc/nftables.d/99-xray-transparent.nft \
    /etc/xray/config.json \
    /etc/xray/conf.d \
    /etc/dnsmasq.d/split.conf \
    /etc/dnsmasq.d/40-cn-domains.conf \
    /root/splittunnel
  do
    if [ -e "$dir$p" ]; then
      run "rm -rf '$p'" || return 1
      run "cp -a '$dir$p' '$p'" || return 1
    fi
  done

  run "ip rule del fwmark $MARK_TPROXY_HEX lookup $TABLE_TPROXY 2>/dev/null || true"
  run "ip rule del fwmark $MARK_WG_HEX lookup $TABLE_WG 2>/dev/null || true"
  run "ip route flush table $TABLE_TPROXY 2>/dev/null || true"
  run "ip route flush table $TABLE_WG 2>/dev/null || true"
  run "nft delete table inet xray_tproxy 2>/dev/null || true"

  run "/etc/init.d/firewall restart || true"
  run "/etc/init.d/dnsmasq restart || true"
  run "/etc/init.d/xray restart || true"

  log "回滚完成。"
  return 0
}

fail() {
  log "部署失败：$1"
  log "建议排查点：$2"
  if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    log "将自动回滚到备份：$BACKUP_DIR"
    rollback_from_dir "$BACKUP_DIR" || log "警告：自动回滚失败，请手动从 $BACKUP_DIR 恢复。"
  else
    log "未发现可用备份目录，无法自动回滚。"
  fi
  exit 1
}

#========================
# 参数解析
#========================
if [ "x$1" = "x--rollback" ]; then
  ROLLBACK_ONLY="1"
fi

#========================
# 开始
#========================
log "============================================================"
log "旁路由分流部署脚本启动（OpenWrt 23.05）"
log "参数：LAN_SUBNET=$LAN_SUBNET MAIN_ROUTER_IP=$MAIN_ROUTER_IP SIDECAR_IP=$SIDECAR_IP WG_IFACE=$WG_IFACE"
log "============================================================"

if [ "$ROLLBACK_ONLY" = "1" ]; then
  latest="$(ls -1d /root/backup-* 2>/dev/null | sort | tail -n 1)"
  if [ -z "$latest" ]; then
    log "回滚失败：未找到 /root/backup-* 备份目录。"
    exit 1
  fi
  rollback_from_dir "$latest" || exit 1
  exit 0
fi

#========================
# 基础自检
#========================
if [ "$(id -u 2>/dev/null)" != "0" ]; then
  fail "必须以 root 执行脚本。" "请使用 root 登录或 sudo -i 后执行。"
fi

run "sh -n '$0'" || fail "脚本自身语法检查失败。" "请检查脚本是否被编辑损坏。"

exists_cmd opkg || fail "未找到 opkg，无法安装依赖。" "确认设备为 OpenWrt 且 opkg 可用。"
exists_cmd nft || fail "未找到 nft 命令。" "请确认系统使用 nftables（fw4）并安装 nft。"
exists_cmd ip || fail "未找到 ip 命令。" "建议安装 ip-full：opkg install ip-full"

if ! ip link show "$WG_IFACE" >/dev/null 2>&1; then
  fail "未检测到 WireGuard 接口：$WG_IFACE" "请确认 wg0 已配置并且接口名固定为 wg0。"
fi

if ! ip link show dev "$WG_IFACE" 2>/dev/null | grep -q "UP"; then
  log "警告：检测到 $WG_IFACE 存在但似乎未 UP。后续自检将给出异常提示。"
fi

#========================
# 创建备份
#========================
make_backup_dir || fail "无法创建备份目录。" "检查 /root 是否可写、空间是否充足。"
log "备份目录：$BACKUP_DIR"

backup_path "/etc/nftables.d/99-xray-transparent.nft" || fail "备份失败。" "检查文件权限与存储空间。"
backup_path "/etc/xray" || fail "备份失败。" "检查文件权限与存储空间。"
backup_path "/etc/dnsmasq.d/split.conf" || fail "备份失败。" "检查文件权限与存储空间。"
backup_path "/etc/dnsmasq.d/40-cn-domains.conf" || fail "备份失败。" "检查文件权限与存储空间。"
backup_path "/root/splittunnel" || fail "备份失败。" "检查文件权限与存储空间。"

#========================
# 安装依赖包
#========================
log "开始安装/补齐依赖包（如已安装则跳过）"
run "opkg update" || fail "opkg update 失败。" "检查 WAN 连接/DNS/系统时间/软件源。"

PKGS="dnsmasq-full xray-core ip-full ca-bundle wget-ssl kmod-nft-tproxy kmod-nft-socket kmod-nf-tproxy"
for p in $PKGS; do
  if opkg status "$p" 2>/dev/null | grep -q "Status: install"; then
    log "依赖已安装：$p"
  else
    run "opkg install '$p'" || fail "安装依赖失败：$p" "检查软件源是否可用、存储空间是否足够。"
  fi
done

#========================
# 写入目录结构与基础文件
#========================
run "mkdir -p /etc/nftables.d /etc/xray/conf.d /etc/dnsmasq.d" || fail "创建目录失败。" "检查只读文件系统或空间不足。"
run "mkdir -p /root/splittunnel/domains /root/splittunnel/ipset /root/splittunnel/templates" || fail "创建目录失败。" "检查 /root 可写性。"

cat > /root/splittunnel/domains/proxy_domains.txt <<'EOF'
# 可维护域名列表（后期扩展位）
# 每行一个域名（不带协议/路径），支持注释与空行
# 部署脚本会把该列表转换为 dnsmasq nftset 规则：
# nftset=/domain/4#inet#xray_tproxy#set_force_wg0_v4
#
# 当前阶段无代理节点：该列表可为空；保留用于后期策略入口。

# 示例（默认注释，不启用）
# google.com
# youtube.com
# openai.com
EOF

cat > /root/splittunnel/README.md <<'EOF'
# OpenWrt 23.05 旁路由分流（nftables + Xray-core + wg0）

## 目标
- CN 流量：在 nftables 层硬绕过，不进 Xray，转发给主路由直连
- 非 CN 流量：TPROXY 进入 Xray，仅用于选择出口，当前默认 wg0 出口
- DNS：非 CN 域名解析走 Xray DNS（127.0.0.1:5353），其对外查询走 wg0，避免泄漏/污染

## 目录说明
- domains/proxy_domains.txt
  后期扩展可维护域名列表。部署脚本会生成 proxy_domains.dnsmasq.conf，用于 dnsmasq nftset 动态写入目的 IP 集合 set_force_wg0_v4。
- ipset/cn4.txt
  CN IPv4 源 CIDR 列表（脚本下载覆盖）。
- ipset/cn4.nft
  nftables interval set 文件（脚本根据 cn4.txt 生成覆盖）。
- templates/
  后期加入代理节点与回退策略模板。

## 设备维度策略
- nft 集合：inet xray_tproxy set_bypass_clients
  把某设备源 IP 加进去后，该设备所有流量（包括非 CN）将绕过 Xray，交给主路由直连（便于灰度/排障）。
  示例：
    nft add element inet xray_tproxy set_bypass_clients { 192.168.88.50 }

## 后期加入 proxy 节点步骤（不要求当前启用）
1) 用 templates/20-outbounds.with_proxy.json 替换 /etc/xray/conf.d/20-outbounds.json，并填好 proxy_out 节点信息。
2) 用 templates/10-routing.with_balancer.json 替换 /etc/xray/conf.d/10-routing.json。
3) （可选）把 domains/proxy_domains.txt 中的域名取消注释/新增，作为更细粒度策略入口。
4) 重启：/etc/init.d/xray restart
EOF

cat > /root/splittunnel/templates/20-outbounds.with_proxy.json <<EOF
{
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" } },
    {
      "tag": "wg0_out",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIPv4" },
      "streamSettings": { "sockopt": { "mark": 2, "interface": "$WG_IFACE" } }
    },
    {
      "tag": "proxy_out",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "YOUR_PROXY_SERVER",
            "port": 443,
            "users": [ { "id": "YOUR_UUID", "encryption": "none", "flow": "" } ]
          }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "tls", "sockopt": { "mark": 2 } }
    },
    { "tag": "dns-out", "protocol": "dns" }
  ]
}
EOF

cat > /root/splittunnel/templates/10-routing.with_balancer.json <<'EOF'
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out" },
      { "type": "field", "inboundTag": ["dns_query"], "outboundTag": "wg0_out" },
      { "type": "field", "ip": ["geoip:private", "geoip:cn"], "outboundTag": "direct" },
      { "type": "field", "domain": ["geosite:private", "geosite:cn"], "outboundTag": "direct" },
      { "type": "field", "domain": ["geosite:geolocation-!cn"], "balancerTag": "b_out" },
      { "type": "field", "inboundTag": ["tproxy-in"], "balancerTag": "b_out" }
    ],
    "balancers": [
      { "tag": "b_out", "selector": ["proxy_out", "wg0_out"], "strategy": { "type": "random" } }
    ]
  }
}
EOF

#========================
# 下载 CN 域名列表（dnsmasq 用）
#========================
log "下载 CN 域名列表（用于 CN 域名走国内 DNS）"
if run "wget -O /etc/dnsmasq.d/40-cn-domains.conf '$CN_DOMAINS_URL'"; then
  log "CN 域名列表下载成功：/etc/dnsmasq.d/40-cn-domains.conf"
else
  log "警告：CN 域名列表下载失败，将继续部署。建议排查点：WAN/DNS/GitHub 访问/时间同步"
fi

#========================
# 下载 CN IPv4 CIDR 并生成 nft set 文件（修复：无尾逗号/去 CRLF/过滤脏行）
#========================
log "下载 CN IPv4 CIDR 并生成 nft set：set_cn4"
if ! run "wget -O /root/splittunnel/ipset/cn4.txt '$CN4_URL'"; then
  fail "CN IPv4 列表下载失败。" "检查 WAN/DNS/GitHub 访问；也可把 cn4.txt 手工放入后重跑脚本。"
fi

run "tr -d '\r' < /root/splittunnel/ipset/cn4.txt > /tmp/cn4.clean.txt" || fail "清洗 cn4.txt 失败。" "检查 /tmp 空间与文件权限。"

awk '
BEGIN{
  print "set set_cn4 {"
  print "  type ipv4_addr"
  print "  flags interval"
  print "  elements = {"
  first=1
}
# 注释/空行跳过
/^[[:space:]]*#/ { next }
/^[[:space:]]*$/ { next }
{
  gsub(/[[:space:]]+/, "", $0)
  if ($0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) {
    if (first==1) { printf "    %s", $0; first=0 }
    else { printf ",\n    %s", $0 }
  }
}
END{
  print "\n  }"
  print "}"
}
' /tmp/cn4.clean.txt > /root/splittunnel/ipset/cn4.nft || fail "生成 cn4.nft 失败。" "检查磁盘空间与文件权限。"

#========================
# 写入 nftables 规则文件（修复：不使用 define 宏；不写空 elements；tproxy 明确指定 ip family）
#========================
cat > /etc/nftables.d/99-xray-transparent.nft <<EOF
#!/usr/sbin/nft -f
# OpenWrt 23.05 fw4 兼容：自定义透明分流表（仅本文件为自定义规则）
# 强制：CN 目的 IP 命中 @set_cn4 立即 return（硬绕过，不进 Xray inbound）

table inet xray_tproxy {

  set set_bypass_clients {
    type ipv4_addr
    flags interval
  }

  set set_force_wg0_v4 {
    type ipv4_addr
    flags interval, timeout
    timeout 6h
  }

  include "/root/splittunnel/ipset/cn4.nft"

  chain prerouting_mangle {
    type filter hook prerouting priority -150; policy accept;

    # 0) 已标记连接：恢复 mark，减少重复判断
    ct mark 1 meta mark set ct mark accept

    # 1) 保留/回环/组播/广播绕过
    ip daddr { 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 } return

    # 2) 私网/保留网段绕过
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } return

    # 3) 本 LAN/主路由/旁路由自身绕过（展开为真实值）
    ip daddr { $LAN_SUBNET, $MAIN_ROUTER_IP, $SIDECAR_IP } return

    # 4) 指定设备绕过
    ip saddr @set_bypass_clients return

    # 5) 【强制硬绕过】CN 目的 IP：必须在任何 tproxy 动作之前 return
    ip daddr @set_cn4 return

    # 6) dnsmasq 动态集合优先引流（关键修复：tproxy 明确指定 ip family）
    ip daddr @set_force_wg0_v4 meta l4proto { tcp, udp } ct state new \\
      ct mark set 1 meta mark set 1 tproxy ip to :$TPROXY_PORT accept

    # 7) 默认：非 CN TCP/UDP 透明引流进入 Xray（关键修复：tproxy 明确指定 ip family）
    meta l4proto { tcp, udp } ct state new \\
      ct mark set 1 meta mark set 1 tproxy ip to :$TPROXY_PORT accept
  }
}
EOF

# 先语法检查，给出明确错误
if ! nft -c -f /etc/nftables.d/99-xray-transparent.nft >/dev/null 2>&1; then
  log "错误：nftables 语法检查失败，以下为 nft 输出（前 120 行）："
  nft -c -f /etc/nftables.d/99-xray-transparent.nft 2>&1 | sed -n '1,120p' | tee -a "$LOG_FILE"
  fail "nftables 规则语法检查未通过。" "重点检查：/root/splittunnel/ipset/cn4.nft 是否有脏行；以及内核模块是否齐全。"
fi


#========================
# 写入 Xray conf.d（工程拆分）
#========================
cat > /etc/xray/conf.d/00-inbounds.json <<EOF
{
  "inbounds": [
    {
      "tag": "tproxy-in",
      "listen": "0.0.0.0",
      "port": $TPROXY_PORT,
      "protocol": "dokodemo-door",
      "settings": { "network": "tcp,udp", "followRedirect": true },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"], "metadataOnly": false },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } }
    },
    {
      "tag": "dns-in",
      "listen": "127.0.0.1",
      "port": $XRAY_DNS_PORT,
      "protocol": "dokodemo-door",
      "settings": { "address": "$FOREIGN_DNS1", "port": 53, "network": "tcp,udp" }
    }
  ]
}
EOF

cat > /etc/xray/conf.d/10-routing.json <<EOF
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out" },
      { "type": "field", "inboundTag": ["dns_query"], "outboundTag": "wg0_out" },
      { "type": "field", "ip": ["geoip:private","geoip:cn"], "outboundTag": "direct" },
      { "type": "field", "domain": ["geosite:private","geosite:cn"], "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["tproxy-in"], "outboundTag": "wg0_out" }
    ]
  }
}
EOF

cat > /etc/xray/conf.d/20-outbounds.json <<EOF
{
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" } },
    {
      "tag": "wg0_out",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIPv4" },
      "streamSettings": { "sockopt": { "mark": 2, "interface": "$WG_IFACE" } }
    },
    { "tag": "dns-out", "protocol": "dns" }
  ]
}
EOF

cat > /etc/xray/conf.d/30-dns.json <<EOF
{
  "dns": {
    "tag": "dns_query",
    "queryStrategy": "UseIPv4",
    "disableCache": false,
    "disableFallback": false,
    "disableFallbackIfMatch": true,
    "useSystemHosts": false,
    "servers": [
      {
        "address": "$DOMESTIC_DNS1",
        "port": 53,
        "domains": ["geosite:cn","geosite:geolocation-cn","geosite:tld-cn"],
        "expectedIPs": ["geoip:cn"],
        "skipFallback": true
      },
      {
        "address": "$MAIN_ROUTER_IP",
        "port": 53,
        "domains": ["geosite:private"],
        "expectedIPs": ["geoip:private"],
        "skipFallback": true
      },
      { "address": "$FOREIGN_DNS1", "port": 53, "skipFallback": false, "queryStrategy": "UseIPv4" },
      { "address": "$FOREIGN_DNS2", "port": 53, "skipFallback": false, "queryStrategy": "UseIPv4" }
    ]
  }
}
EOF

cat > /etc/xray/config.json <<EOF
{
  "log": { "access": "/tmp/xray-access.log", "error": "/tmp/xray-error.log", "loglevel": "warning" },
  "include": [
    "/etc/xray/conf.d/00-inbounds.json",
    "/etc/xray/conf.d/10-routing.json",
    "/etc/xray/conf.d/20-outbounds.json",
    "/etc/xray/conf.d/30-dns.json"
  ]
}
EOF

#========================
# 写入 dnsmasq 分流配置
#========================
cat > /etc/dnsmasq.d/split.conf <<EOF
listen-address=$SIDECAR_IP
listen-address=127.0.0.1
bind-dynamic
port=53

domain-needed
bogus-priv
no-negcache
cache-size=10000
min-cache-ttl=60

no-resolv
server=127.0.0.1#$XRAY_DNS_PORT

conf-file=/root/splittunnel/domains/proxy_domains.dnsmasq.conf
EOF

run "rm -f /root/splittunnel/domains/proxy_domains.dnsmasq.conf"
run "touch /root/splittunnel/domains/proxy_domains.dnsmasq.conf"

while IFS= read -r line; do
  echo "$line" | grep -q "^[[:space:]]*#" && continue
  echo "$line" | grep -q "^[[:space:]]*$" && continue
  d="$(echo "$line" | tr -d "[:space:]")"
  echo "nftset=/$d/4#inet#xray_tproxy#set_force_wg0_v4" >> /root/splittunnel/domains/proxy_domains.dnsmasq.conf
done < /root/splittunnel/domains/proxy_domains.txt

#========================
# geosite/geoip 数据文件
#========================
DAT_DIR="/usr/share/xray"
run "mkdir -p '$DAT_DIR'" || fail "创建 Xray 数据目录失败：$DAT_DIR" "检查只读文件系统或空间不足。"

if [ ! -s "$DAT_DIR/geoip.dat" ]; then
  log "下载 geoip.dat"
  if ! run "wget -O '$DAT_DIR/geoip.dat' '$GEOIP_URL'"; then
    log "警告：geoip.dat 下载失败。建议排查点：WAN/DNS/GitHub 访问/时间同步"
  fi
fi

if [ ! -s "$DAT_DIR/geosite.dat" ]; then
  log "下载 geosite.dat"
  if ! run "wget -O '$DAT_DIR/geosite.dat' '$GEOSITE_URL'"; then
    log "警告：geosite.dat 下载失败。建议排查点：WAN/DNS/GitHub 访问/时间同步"
  fi
fi

#========================
# sysctl（TPROXY 常见必要项）
#========================
run "sysctl -w net.ipv4.ip_forward=1 >/dev/null"
run "sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null"
run "sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null"

#========================
# 策略路由（强制）
#========================
log "设置策略路由：mark=$MARK_TPROXY_HEX -> table $TABLE_TPROXY -> local lo（TPROXY 回环）"
run "ip rule del fwmark $MARK_TPROXY_HEX lookup $TABLE_TPROXY 2>/dev/null || true"
run "ip route flush table $TABLE_TPROXY 2>/dev/null || true"
run "ip rule add fwmark $MARK_TPROXY_HEX lookup $TABLE_TPROXY priority 100" || fail "添加 ip rule 失败（TPROXY 回环）" "检查 ip-full 是否安装、内核策略路由是否可用。"
run "ip route add local 0.0.0.0/0 dev lo table $TABLE_TPROXY" || fail "添加 ip route 失败（TPROXY 回环）" "检查 lo 设备与 table 是否冲突。"

log "设置策略路由：mark=$MARK_WG_HEX -> table $TABLE_WG -> default dev $WG_IFACE（wg0 出口）"
run "ip rule del fwmark $MARK_WG_HEX lookup $TABLE_WG 2>/dev/null || true"
run "ip route flush table $TABLE_WG 2>/dev/null || true"
run "ip rule add fwmark $MARK_WG_HEX lookup $TABLE_WG priority 110" || fail "添加 ip rule 失败（wg0 出口）" "检查 ip-full 是否安装、内核策略路由是否可用。"
run "ip route add default dev $WG_IFACE table $TABLE_WG" || fail "添加 ip route 失败（wg0 出口）" "检查 wg0 是否存在/是否 UP。"

#========================
# 载入 nftables
#========================
log "载入 nftables 规则（并确保不重复）"
run "nft delete table inet xray_tproxy 2>/dev/null || true"
run "nft -f /etc/nftables.d/99-xray-transparent.nft" || fail "nftables 载入失败。" "建议先执行：nft -c -f /etc/nftables.d/99-xray-transparent.nft 查看具体报错。"

#========================
# Xray include 降级逻辑（强制）
#========================
log "测试 Xray 配置：优先使用 include 结构"
if run "xray run -test -config /etc/xray/config.json"; then
  log "Xray include 配置测试通过：将直接使用 /etc/xray/config.json"
else
  log "Xray include 配置测试失败：将自动生成等价单文件 /etc/xray/config.json 并再次测试"
  cat > /etc/xray/config.json <<EOF
{
  "log": { "access": "/tmp/xray-access.log", "error": "/tmp/xray-error.log", "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "tproxy-in",
      "listen": "0.0.0.0",
      "port": $TPROXY_PORT,
      "protocol": "dokodemo-door",
      "settings": { "network": "tcp,udp", "followRedirect": true },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"], "metadataOnly": false },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } }
    },
    {
      "tag": "dns-in",
      "listen": "127.0.0.1",
      "port": $XRAY_DNS_PORT,
      "protocol": "dokodemo-door",
      "settings": { "address": "$FOREIGN_DNS1", "port": 53, "network": "tcp,udp" }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "AsIs" } },
    {
      "tag": "wg0_out",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIPv4" },
      "streamSettings": { "sockopt": { "mark": 2, "interface": "$WG_IFACE" } }
    },
    { "tag": "dns-out", "protocol": "dns" }
  ],
  "dns": {
    "tag": "dns_query",
    "queryStrategy": "UseIPv4",
    "disableCache": false,
    "disableFallback": false,
    "disableFallbackIfMatch": true,
    "useSystemHosts": false,
    "servers": [
      {
        "address": "$DOMESTIC_DNS1",
        "port": 53,
        "domains": ["geosite:cn","geosite:geolocation-cn","geosite:tld-cn"],
        "expectedIPs": ["geoip:cn"],
        "skipFallback": true
      },
      {
        "address": "$MAIN_ROUTER_IP",
        "port": 53,
        "domains": ["geosite:private"],
        "expectedIPs": ["geoip:private"],
        "skipFallback": true
      },
      { "address": "$FOREIGN_DNS1", "port": 53, "skipFallback": false, "queryStrategy": "UseIPv4" },
      { "address": "$FOREIGN_DNS2", "port": 53, "skipFallback": false, "queryStrategy": "UseIPv4" }
    ]
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out" },
      { "type": "field", "inboundTag": ["dns_query"], "outboundTag": "wg0_out" },
      { "type": "field", "ip": ["geoip:private","geoip:cn"], "outboundTag": "direct" },
      { "type": "field", "domain": ["geosite:private","geosite:cn"], "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["tproxy-in"], "outboundTag": "wg0_out" }
    ]
  }
}
EOF
  run "xray run -test -config /etc/xray/config.json" || fail "Xray 单文件配置测试仍失败。" "查看 /tmp/xray-error.log 与 $LOG_FILE，检查 JSON 语法与字段兼容性。"
  log "Xray 单文件配置测试通过：已降级为单文件运行模式"
fi

#========================
# 重启服务（强制）
#========================
log "重启/重载服务：network / firewall / dnsmasq / xray"
run "/etc/init.d/network reload || true"
run "/etc/init.d/firewall restart" || fail "firewall 重启失败。" "检查 fw4 状态：logread -e fw4；nft list ruleset。"
run "/etc/init.d/dnsmasq restart" || fail "dnsmasq 重启失败。" "检查 dnsmasq-full 是否安装、配置是否冲突。"
run "/etc/init.d/xray restart" || fail "xray 重启失败。" "检查 /etc/xray/config.json 与 /tmp/xray-error.log。"

#========================
# 部署后中文自检摘要（强制）
#========================
log "==================== 部署后自检摘要 ===================="

if ip link show "$WG_IFACE" >/dev/null 2>&1; then
  if ip link show dev "$WG_IFACE" 2>/dev/null | grep -q "UP"; then
    log "wg0 状态：正常（存在且 UP）"
  else
    log "wg0 状态：异常（存在但未 UP）"
  fi
else
  log "wg0 状态：异常（接口不存在）"
fi

if nft list chain inet xray_tproxy prerouting_mangle >/dev/null 2>&1; then
  log "nftables 规则：正常（inet xray_tproxy/prerouting_mangle 已加载）"
else
  log "nftables 规则：异常（未找到 inet xray_tproxy/prerouting_mangle）"
fi

CN_CNT="$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -c '/' 2>/dev/null)"
if [ -n "$CN_CNT" ] && [ "$CN_CNT" -gt 0 ]; then
  log "CN 集合元素：正常（疑似条目数 > 0，计数=$CN_CNT）"
else
  log "CN 集合元素：异常（条目数可能为 0 或读取失败）"
fi

if ss -ntulp 2>/dev/null | grep -q ":$TPROXY_PORT"; then
  log "Xray 监听：正常（TPROXY 端口 $TPROXY_PORT 已监听）"
else
  log "Xray 监听：异常（未检测到 $TPROXY_PORT 监听）"
fi

DNSMASQ_CONF="$(ls -1 /var/etc/dnsmasq.conf.* 2>/dev/null | head -n 1)"
if [ -n "$DNSMASQ_CONF" ]; then
  if dnsmasq --test -C "$DNSMASQ_CONF" >/dev/null 2>&1; then
    log "dnsmasq 配置：正常（dnsmasq --test 通过，主配置=$DNSMASQ_CONF）"
  else
    log "dnsmasq 配置：异常（dnsmasq --test 未通过，主配置=$DNSMASQ_CONF）"
  fi
else
  log "dnsmasq 配置：提示（未找到 /var/etc/dnsmasq.conf.*，无法进行 --test 定位）"
fi

if nft list chain inet xray_tproxy prerouting_mangle >/dev/null 2>&1 && ss -ntulp 2>/dev/null | grep -q ":$TPROXY_PORT"; then
  log "总体判定：正常（分流核心组件已就绪）"
else
  log "总体判定：异常（分流核心组件不完整，请按日志排查）"
fi

log "日志文件：$LOG_FILE"
log "==================== 部署完成 ===================="
exit 0
