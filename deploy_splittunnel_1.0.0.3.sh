#!/bin/sh
# ============================================================================
# OpenWrt 23.05 旁路由分流系统 - 一键部署脚本（Fixed v7）
# 日期: 2026-01-07
# 兼容: BusyBox sh
#
# 关键修复:
#  - 禁止 WireGuard 将 AllowedIPs(0/0) 路由写入主路由表: route_allowed_ips=0
#  - 强制 firewall 允许转发: defaults.forward=ACCEPT, lan.forward=ACCEPT
#  - dnsmasq: 不写 bind-interfaces; UCI 删除 nonwildcard 避免 bind-dynamic 冲突
#  - 默认 filteraaaa=1 强制 IPv4，避免 IPv6 导致浏览器打不开/绕过分流
#  - nft tproxy 带 counter；并清理重复 include，避免规则重复注入
# ============================================================================

set -e

# -------------------------
# 配置变量
# -------------------------
LAN_SUBNET="192.168.88.0/24"
MAIN_ROUTER_IP="192.168.88.1"
SIDECAR_IP="192.168.88.200"
WG_IFACE="wg0"

XRAY_TPROXY_PORT="12345"
XRAY_DNS_PORT="5353"
XRAY_TPROXY_MARK="0x1"
XRAY_WG_MARK="0x2"

TABLE_TPROXY="100"
TABLE_WG="200"

SPLITTUNNEL_DIR="/root/splittunnel"
BACKUP_DIR="/root/backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/root/deploy_splittunnel.log"

CNIP_URL="https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"

NFT_RULESET_FILE="/etc/nftables.xray_tproxy.nft"
NFT_CN_LOAD_FILE="$SPLITTUNNEL_DIR/ipset/cn4.nft"
FW_INCLUDE_NAME="xray_tproxy_include"

XRAY_SERVICE_NAME="splittunnel-xray"
XRAY_INIT="/etc/init.d/${XRAY_SERVICE_NAME}"

# 默认开启：过滤 AAAA（强制 IPv4）
ENABLE_FILTER_AAAA="1"

# -------------------------
# 日志
# -------------------------
log_info()    { echo "[信息] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_warn()    { echo "[警告] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_error()   { echo "[错误] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_success() { echo "[成功] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }

cleanup_on_error() {
  log_error "部署过程中发生错误（第 $1 行）"
  log_error "请查看日志：$LOG_FILE"
  exit 1
}
trap 'cleanup_on_error $LINENO' ERR

# -------------------------
# 小工具
# -------------------------
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { log_error "缺少命令：$1"; exit 1; }
}

detect_lan_iface() {
  LAN_IFACE="$(uci -q get network.lan.device || true)"
  [ -n "$LAN_IFACE" ] || LAN_IFACE="$(uci -q get network.lan.ifname || true)"
  [ -n "$LAN_IFACE" ] || LAN_IFACE="br-lan"
  log_info "检测到 LAN_IFACE=$LAN_IFACE"
}

ip_has_addr() {
  ip -4 addr show 2>/dev/null | grep -q "inet $1/"
}

# -------------------------
# 预检
# -------------------------
preflight_check() {
  log_info "========== 预检 =========="
  [ "$(id -u)" -eq 0 ] || { log_error "必须 root 运行"; exit 1; }
  [ -f /etc/openwrt_release ] || { log_error "未检测到 OpenWrt"; exit 1; }

  need_cmd uci
  need_cmd ip
  need_cmd nft
  need_cmd wg
  need_cmd ss
  need_cmd wget
  need_cmd opkg

  detect_lan_iface

  ip link show "$WG_IFACE" >/dev/null 2>&1 || { log_error "WireGuard 接口不存在：$WG_IFACE"; exit 1; }

  if ! lsmod | grep -q "nft_tproxy"; then
    log_info "加载 nft_tproxy 内核模块..."
    modprobe nft_tproxy 2>/dev/null || { log_error "nft_tproxy 加载失败"; exit 1; }
  fi

  log_success "预检通过"
}

# -------------------------
# 备份
# -------------------------
backup_configs() {
  log_info "========== 备份 =========="
  mkdir -p "$BACKUP_DIR"
  [ -f "$NFT_RULESET_FILE" ] && cp "$NFT_RULESET_FILE" "$BACKUP_DIR/" 2>/dev/null || true
  [ -d /etc/xray ] && cp -r /etc/xray "$BACKUP_DIR/" 2>/dev/null || true
  [ -d /etc/dnsmasq.d ] && cp -r /etc/dnsmasq.d "$BACKUP_DIR/" 2>/dev/null || true
  uci show firewall > "$BACKUP_DIR/uci_firewall.txt" 2>/dev/null || true
  uci show dhcp > "$BACKUP_DIR/uci_dhcp.txt" 2>/dev/null || true
  uci show network > "$BACKUP_DIR/uci_network.txt" 2>/dev/null || true
  ip rule show > "$BACKUP_DIR/ip_rules.txt" 2>/dev/null || true
  ip route show > "$BACKUP_DIR/ip_route_main.txt" 2>/dev/null || true
  ip route show table "$TABLE_TPROXY" > "$BACKUP_DIR/route_${TABLE_TPROXY}.txt" 2>/dev/null || true
  ip route show table "$TABLE_WG" > "$BACKUP_DIR/route_${TABLE_WG}.txt" 2>/dev/null || true
  log_success "备份完成：$BACKUP_DIR"
}

# -------------------------
# 安装依赖
# -------------------------
install_dependencies() {
  log_info "========== 安装依赖 =========="
  opkg update 2>&1 | tee -a "$LOG_FILE" || log_warn "opkg update 失败，继续"

  for pkg in dnsmasq-full xray-core kmod-nft-tproxy ip-full curl wget-ssl; do
    if opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
      log_info "$pkg 已安装，跳过"
    else
      log_info "安装 $pkg ..."
      opkg install "$pkg" 2>&1 | tee -a "$LOG_FILE"
    fi
  done
  log_success "依赖检查完成"
}

# -------------------------
# sysctl
# -------------------------
apply_sysctl_tproxy() {
  log_info "========== 配置 TPROXY 必需 sysctl =========="
  cat >/etc/sysctl.d/99-xray-tproxy.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.default.route_localnet=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  sysctl -p /etc/sysctl.d/99-xray-tproxy.conf 2>&1 | tee -a "$LOG_FILE" || true
  log_success "sysctl 配置完成"
}

# -------------------------
# 确保稳定 IP（alias）
# -------------------------
ensure_sidecar_ip_alias() {
  log_info "========== 确保稳定 IP: $SIDECAR_IP =========="
  if ip_has_addr "$SIDECAR_IP"; then
    log_success "稳定 IP 已存在：$SIDECAR_IP"
    return 0
  fi

  uci -q delete network.splittunnel_alias || true
  uci set network.splittunnel_alias='interface'
  uci set network.splittunnel_alias.proto='static'
  uci set network.splittunnel_alias.device="$LAN_IFACE"
  uci set network.splittunnel_alias.ipaddr="$SIDECAR_IP"
  uci set network.splittunnel_alias.netmask='255.255.255.0'
  uci commit network

  /etc/init.d/network reload 2>&1 | tee -a "$LOG_FILE" || true
  sleep 2

  ip_has_addr "$SIDECAR_IP" || { log_error "alias 创建失败：$SIDECAR_IP 不存在"; return 1; }
  log_success "alias 创建成功：$SIDECAR_IP"
}

# -------------------------
# 关键：禁用 wg 自动路由写入主表（route_allowed_ips=0）
# -------------------------
fix_wireguard_routes() {
  log_info "========== 修复 WireGuard 自动路由（主表污染） =========="

  # 尝试直接对 network.wg0 生效（你的接口名就是 wg0）
  cur="$(uci -q get network.${WG_IFACE}.route_allowed_ips || true)"
  if [ "$cur" != "0" ]; then
    uci -q set network.${WG_IFACE}.route_allowed_ips='0'
    uci commit network
    log_success "已设置 network.${WG_IFACE}.route_allowed_ips=0"
  else
    log_info "network.${WG_IFACE}.route_allowed_ips 已是 0"
  fi

  /etc/init.d/network reload 2>&1 | tee -a "$LOG_FILE" || true
  sleep 2

  # 如果主路由表里存在默认走 wg0，干掉它（只删“dev wg0 的 default”）
  if ip route show | grep -q "^default .* dev ${WG_IFACE}\b"; then
    log_warn "检测到主路由表 default dev ${WG_IFACE}，将删除以避免全局走 wg"
    ip route del default dev "${WG_IFACE}" 2>/dev/null || true
  fi

  log_success "WireGuard 路由修复完成"
}

# -------------------------
# firewall：允许转发（旁路由做网关必须）
# -------------------------
fix_firewall_forwarding() {
  log_info "========== 修复 firewall 转发策略 =========="

  # defaults forward=ACCEPT
  uci -q set firewall.@defaults[0].forward='ACCEPT'

  # lan zone forward=ACCEPT（找到 name='lan' 的 zone）
  lan_zone=""
  for z in $(uci show firewall | awk -F'[.=]' '/=zone$/{print $2}' | sort -u); do
    n="$(uci -q get firewall.$z.name || true)"
    [ "$n" = "lan" ] && lan_zone="$z"
  done
  if [ -n "$lan_zone" ]; then
    uci -q set firewall.$lan_zone.forward='ACCEPT'
    uci -q set firewall.$lan_zone.input='ACCEPT'
    uci -q set firewall.$lan_zone.output='ACCEPT'
    log_success "已设置 firewall.$lan_zone(lan) forward/input/output=ACCEPT"
  else
    log_warn "未找到 lan zone（name=lan），仅设置 defaults.forward=ACCEPT"
  fi

  uci commit firewall
  /etc/init.d/firewall reload 2>&1 | tee -a "$LOG_FILE" || true
  log_success "firewall 转发策略修复完成"
}

# -------------------------
# dnsmasq：DNS-only + 兼容 bind-dynamic + 可选 filteraaaa
# -------------------------
configure_dnsmasq_uci() {
  log_info "========== 配置 dnsmasq（UCI） =========="

  mkdir -p /etc/dnsmasq.d

  # 禁用所有 DHCP 段（避免与主路由冲突）
  for s in $(uci show dhcp | awk -F'[.=]' '/=dhcp$/{print $2}' | sort -u); do
    uci -q set dhcp.$s.ignore='1'
  done

  # 全局参数（不要写进 split.conf，避免重复关键字）
  uci -q set dhcp.@dnsmasq[0].confdir='/etc/dnsmasq.d'
  uci -q set dhcp.@dnsmasq[0].noresolv='1'
  uci -q set dhcp.@dnsmasq[0].strictorder='1'
  uci -q set dhcp.@dnsmasq[0].cachesize='10000'

  # 关键：避免 bind-interfaces 与默认 bind-dynamic 冲突
  uci -q delete dhcp.@dnsmasq[0].nonwildcard || true

  if [ "$ENABLE_FILTER_AAAA" = "1" ]; then
    uci -q set dhcp.@dnsmasq[0].filteraaaa='1'
  else
    uci -q delete dhcp.@dnsmasq[0].filteraaaa || true
  fi

  uci commit dhcp
  log_success "dnsmasq UCI 配置完成（DNS-only + noresolv/strictorder/cachesize + nonwildcard off + filteraaaa=$ENABLE_FILTER_AAAA）"
}

deploy_dnsmasq_splitconf() {
  log_info "========== 写入 /etc/dnsmasq.d/split.conf =========="
  mkdir -p /etc/dnsmasq.d

  cat > /etc/dnsmasq.d/split.conf <<EOF
# Split DNS include file (KEEP MINIMAL)
# IMPORTANT: do NOT set "bind-interfaces" here (OpenWrt defaults to bind-dynamic)

server=127.0.0.1#$XRAY_DNS_PORT

server=/.cn/223.5.5.5
server=/.qq.com/223.5.5.5
server=/.163.com/223.5.5.5
server=/.sina.com.cn/223.5.5.5
server=/.baidu.com/223.5.5.5
server=/.taobao.com/223.5.5.5
server=/.tmall.com/223.5.5.5
server=/.jd.com/223.5.5.5
server=/.alipay.com/223.5.5.5
server=/.weibo.com/223.5.5.5
server=/.bilibili.com/223.5.5.5
server=/.douyin.com/223.5.5.5
server=/.toutiao.com/223.5.5.5
server=/.gov.cn/223.5.5.5
server=/.edu.cn/223.5.5.5

interface=$LAN_IFACE
listen-address=$SIDECAR_IP
EOF

  log_success "split.conf 已写入（最小化）"
}

# -------------------------
# 下载 CN IP + 生成 nft load 文件
# -------------------------
download_cnip() {
  log_info "========== 下载 CN IP =========="
  mkdir -p "$SPLITTUNNEL_DIR/ipset"
  wget -T 30 -O "$SPLITTUNNEL_DIR/ipset/cn4.txt" "$CNIP_URL" 2>&1 | tee -a "$LOG_FILE"
  [ -f "$SPLITTUNNEL_DIR/ipset/cn4.txt" ] || { log_error "CN IP 文件不存在"; return 1; }
  CNIP_COUNT=$(wc -l < "$SPLITTUNNEL_DIR/ipset/cn4.txt")
  [ "$CNIP_COUNT" -ge 1000 ] || { log_error "CN IP 数据异常：$CNIP_COUNT"; return 1; }
  log_success "CN IP 下载完成：$CNIP_COUNT 条"
}

generate_cnip_nft_loader() {
  log_info "========== 生成 CN 集合加载文件 =========="
  mkdir -p "$SPLITTUNNEL_DIR/ipset"
  cat > "$NFT_CN_LOAD_FILE" <<'EOFCN'
add element inet xray_tproxy set_cn4 {
EOFCN
  awk '{print "  "$1","}' "$SPLITTUNNEL_DIR/ipset/cn4.txt" >> "$NFT_CN_LOAD_FILE"
  echo "}" >> "$NFT_CN_LOAD_FILE"
  log_success "CN 集合加载文件生成：$NFT_CN_LOAD_FILE"
}

# -------------------------
# 防止 firewall include 重复（导致 nft 规则重复注入）
# -------------------------
cleanup_duplicate_firewall_includes() {
  log_info "========== 清理重复 firewall include =========="
  for sec in $(uci show firewall | awk -F'[.=]' '/=include$/{print $2}' | sort -u); do
    p="$(uci -q get firewall.$sec.path || true)"
    t="$(uci -q get firewall.$sec.type || true)"
    if [ "$t" = "nftables" ] && [ "$p" = "$NFT_RULESET_FILE" ]; then
      uci -q delete firewall.$sec || true
      log_info "删除重复 include: firewall.$sec (path=$p)"
    fi
  done
  uci -q delete firewall.$FW_INCLUDE_NAME || true
  uci commit firewall
  log_success "重复 include 清理完成"
}

# -------------------------
# 部署 nftables（带 counter，且 reload 前 delete table 保证干净）
# -------------------------
deploy_nftables() {
  log_info "========== 部署 nftables =========="

  cat > "$NFT_RULESET_FILE" <<EOF
table inet xray_tproxy {
  set set_cn4 {
    type ipv4_addr
    flags interval
  }

  chain prerouting_mangle {
    type filter hook prerouting priority mangle; policy accept;

    meta l4proto != { tcp, udp } return
    ip saddr != $LAN_SUBNET return

    ip daddr { $MAIN_ROUTER_IP, $SIDECAR_IP } return
    ip daddr @set_cn4 return

    ip daddr {
      0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8,
      169.254.0.0/16, 172.16.0.0/12,
      192.168.0.0/16, 224.0.0.0/3
    } return

    meta l4proto tcp counter tproxy ip to 127.0.0.1:$XRAY_TPROXY_PORT meta mark set $XRAY_TPROXY_MARK
    meta l4proto udp counter tproxy ip to 127.0.0.1:$XRAY_TPROXY_PORT meta mark set $XRAY_TPROXY_MARK
  }
}
EOF
  log_success "已写入 nft ruleset：$NFT_RULESET_FILE"

  cleanup_duplicate_firewall_includes

  uci set firewall.$FW_INCLUDE_NAME=include
  uci set firewall.$FW_INCLUDE_NAME.type='nftables'
  uci set firewall.$FW_INCLUDE_NAME.path="$NFT_RULESET_FILE"
  uci set firewall.$FW_INCLUDE_NAME.position='ruleset-pre'
  uci commit firewall
  log_success "已配置 firewall include（唯一）：$FW_INCLUDE_NAME"

  nft delete table inet xray_tproxy 2>/dev/null || true
  /etc/init.d/firewall reload 2>&1 | tee -a "$LOG_FILE" || true
  nft list table inet xray_tproxy >/dev/null 2>&1 || { log_error "nft table 未加载"; return 1; }

  log_info "加载 CN IP 集合..."
  nft -f "$NFT_CN_LOAD_FILE" 2>&1 | tee -a "$LOG_FILE"

  CN_COUNT=$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -o "[0-9.]\+/[0-9]\+" | wc -l)
  [ "$CN_COUNT" -ge 100 ] || { log_error "CN 集合数量异常：$CN_COUNT"; return 1; }

  log_success "nftables 部署完成，CN 集合条目：$CN_COUNT"
}

# -------------------------
# Xray（单文件）+ procd 服务
#   注意：tproxy inbound 不再设置 sockopt.mark，避免与 fwmark(0x1) 策略路由潜在打架
# -------------------------
deploy_xray_config() {
  log_info "========== 部署 Xray 配置 =========="
  mkdir -p /etc/xray

  WG_MARK_DEC=$((XRAY_WG_MARK))

  cat > /etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/tmp/xray_access.log",
    "error": "/tmp/xray_error.log"
  },
  "inbounds": [
    {
      "tag": "tproxy_in",
      "protocol": "dokodemo-door",
      "listen": "127.0.0.1",
      "port": $XRAY_TPROXY_PORT,
      "settings": { "network": "tcp,udp", "followRedirect": true },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"], "metadataOnly": false },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } }
    },
    {
      "tag": "dns_in",
      "protocol": "dokodemo-door",
      "listen": "127.0.0.1",
      "port": $XRAY_DNS_PORT,
      "settings": { "address": "1.1.1.1", "port": 53, "network": "udp" }
    }
  ],
  "outbounds": [
    {
      "tag": "wg0_out",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIP" },
      "streamSettings": { "sockopt": { "mark": $WG_MARK_DEC } }
    },
    { "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "UseIP" } }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["dns_in"], "outboundTag": "wg0_out" },
      { "type": "field", "inboundTag": ["tproxy_in"], "domain": ["geosite:cn"], "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["tproxy_in"], "ip": ["geoip:cn","geoip:private"], "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["tproxy_in"], "outboundTag": "wg0_out" }
    ]
  },
  "dns": {
    "servers": [
      { "address": "223.5.5.5", "port": 53, "domains": ["geosite:cn"], "expectIPs": ["geoip:cn"] },
      { "address": "1.1.1.1", "port": 53, "domains": [] }
    ],
    "queryStrategy": "UseIPv4",
    "disableCache": false,
    "disableFallback": true
  }
}
EOF

  log_info "测试 Xray 配置..."
  xray run -test -config /etc/xray/config.json 2>&1 | tee -a "$LOG_FILE"
  log_success "Xray 配置测试通过"
}

deploy_xray_service() {
  log_info "========== 部署 Xray procd 服务：$XRAY_SERVICE_NAME =========="

  cat > "$XRAY_INIT" <<'EOF'
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1

BIN=/usr/bin/xray
CONFIG=/etc/xray/config.json

start_service() {
  procd_open_instance
  procd_set_param command "$BIN" run -config "$CONFIG"
  procd_set_param respawn 3600 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
EOF
  chmod +x "$XRAY_INIT"

  /etc/init.d/xray stop 2>/dev/null || true
  "$XRAY_INIT" enable 2>/dev/null || true
  "$XRAY_INIT" restart 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  log_success "$XRAY_SERVICE_NAME 已启动"
}

# -------------------------
# 策略路由（只让 mark 0x2 走 wg0；TPROXY mark 0x1 回环）
# -------------------------
configure_policy_routing() {
  log_info "========== 配置策略路由 =========="

  ip rule del fwmark "$XRAY_TPROXY_MARK" table "$TABLE_TPROXY" 2>/dev/null || true
  ip rule del fwmark "$XRAY_WG_MARK" table "$TABLE_WG" 2>/dev/null || true

  ip rule add fwmark "$XRAY_TPROXY_MARK" table "$TABLE_TPROXY" pref 1000
  ip rule add fwmark "$XRAY_WG_MARK" table "$TABLE_WG" pref 1001

  ip route flush table "$TABLE_TPROXY" 2>/dev/null || true
  ip route add local default dev lo table "$TABLE_TPROXY"

  ip route flush table "$TABLE_WG" 2>/dev/null || true
  ip route add default dev "$WG_IFACE" table "$TABLE_WG"

  log_success "策略路由配置完成"
}

# -------------------------
# 重启服务
# -------------------------
restart_services() {
  log_info "========== 重启相关服务 =========="

  /etc/init.d/network reload 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  /etc/init.d/firewall reload 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  "$XRAY_INIT" restart 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  log_info "启动 dnsmasq..."
  if pidof dnsmasq >/dev/null 2>&1; then
    /etc/init.d/dnsmasq stop 2>&1 | tee -a "$LOG_FILE" || true
    sleep 1
  fi
  /etc/init.d/dnsmasq start 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  log_success "服务重启完成"
}

# -------------------------
# 自检（看 counter + 看 wg 传输是否增长）
# -------------------------
post_check() {
  log_info "========== 部署后自检 =========="
  ERR=0

  ip_has_addr "$SIDECAR_IP" && log_success "✓ 稳定 IP 存在：$SIDECAR_IP" || { log_error "✗ 稳定 IP 不存在"; ERR=$((ERR+1)); }

  nft list table inet xray_tproxy >/dev/null 2>&1 && log_success "✓ nft table OK" || { log_error "✗ nft table missing"; ERR=$((ERR+1)); }

  ss -lntp 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT" && log_success "✓ Xray TCP $XRAY_TPROXY_PORT 监听" || { log_error "✗ Xray TCP 未监听"; ERR=$((ERR+1)); }
  ss -lnup 2>/dev/null | grep -q ":$XRAY_DNS_PORT" && log_success "✓ Xray UDP $XRAY_DNS_PORT 监听" || { log_error "✗ Xray UDP 未监听"; ERR=$((ERR+1)); }

  pidof dnsmasq >/dev/null 2>&1 && log_success "✓ dnsmasq 运行中" || { log_error "✗ dnsmasq 未运行"; ERR=$((ERR+1)); }

  log_info "tproxy counter（访问国外网站后应增长）："
  nft -a list chain inet xray_tproxy prerouting_mangle 2>/dev/null | grep -n "counter" | tee -a "$LOG_FILE" || true

  log_info "wg0 传输统计（访问国外网站后应增长）："
  wg show "$WG_IFACE" 2>/dev/null | sed -n '1,120p' | tee -a "$LOG_FILE" || true

  if [ "$ERR" -eq 0 ]; then
    log_success "✓ 自检通过"
  else
    log_error "✗ 自检发现 $ERR 个问题"
    log_info "排查建议："
    log_info "  - logread | grep -i dnsmasq | tail -n 80"
    log_info "  - cat /tmp/xray_error.log"
    log_info "  - ip route show | head -n 30"
    log_info "  - nft -a list chain inet xray_tproxy prerouting_mangle"
  fi
}

# -------------------------
# 主流程
# -------------------------
main() {
  log_info "========================================="
  log_info "OpenWrt 23.05 Split Tunnel Deploy (Fixed v7)"
  log_info "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
  log_info "========================================="

  preflight_check
  backup_configs
  install_dependencies

  apply_sysctl_tproxy
  ensure_sidecar_ip_alias

  fix_wireguard_routes
  fix_firewall_forwarding

  configure_dnsmasq_uci
  deploy_dnsmasq_splitconf

  download_cnip
  generate_cnip_nft_loader
  deploy_nftables

  deploy_xray_config
  deploy_xray_service

  configure_policy_routing

  restart_services
  post_check

  log_info "========================================="
  log_success "✓ Deployment Complete!"
  log_info "Backup Directory: $BACKUP_DIR"
  log_info "Log File: $LOG_FILE"
  log_info "客户端建议设置："
  log_info "  网关: $SIDECAR_IP"
  log_info "  DNS : $SIDECAR_IP"
  log_info "验证分流：打开一个国外网站，然后旁路由看："
  log_info "  nft -a list chain inet xray_tproxy prerouting_mangle | grep -n counter"
  log_info "  wg show wg0"
  log_info "========================================="
}

main "$@"
