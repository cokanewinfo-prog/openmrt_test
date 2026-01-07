#!/bin/sh
# ============================================================================
# OpenWrt 23.05 旁路由分流系统 - 一键部署脚本（修复版 + 合并 BBR）
# 模式: IP 分流为主 + 域名强制走 wg（补丁）
# 流程: nftables(TPROXY) + Xray(TPROXY+DNS) + dnsmasq(最小化 split.conf)
# 兼容: BusyBox sh
# 日期: 2026-01-08
# ============================================================================

set -e

# ========== 配置变量（集中定义） ==========

LAN_SUBNET="192.168.88.0/24"
MAIN_ROUTER_IP="192.168.88.1"
SIDECAR_IP="192.168.88.200"
LAN_IFACE="br-lan"
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

# CNIP（优先走 wg0 下载）
CNIP_URL="https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"

# 域名强制走 wg0（补丁列表：可自行扩展）
FORCE_WG_DOMAINS="
geosite:geolocation-!cn
domain:google.com
domain:youtube.com
domain:googlevideo.com
domain:gstatic.com
domain:googleapis.com
domain:ggpht.com
domain:ytimg.com
domain:github.com
domain:githubusercontent.com
domain:raw.githubusercontent.com
domain:cloudflare.com
domain:cloudflare-dns.com
domain:1dot1dot1dot1.cloudflare-dns.com
domain:telegram.org
domain:t.me
domain:twitter.com
domain:x.com
domain:facebook.com
domain:fbcdn.net
domain:instagram.com
domain:whatsapp.com
domain:wikipedia.org
domain:reddit.com
domain:openai.com
domain:chatgpt.com
"

# ========== 日志函数 ==========

log_info()    { echo "[信息] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_warn()    { echo "[警告] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_error()   { echo "[错误] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_success() { echo "[成功] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }

# ========== 错误处理 ==========

cleanup_on_error() {
  log_error "部署过程中发生错误"
  log_error "错误位置: 第 $1 行"
  log_error "建议操作: 查看日志文件 $LOG_FILE"
  log_info "尝试回滚到部署前状态..."
  rollback || true
  exit 1
}
trap 'cleanup_on_error $LINENO' ERR

# ========== 自检函数 ==========

preflight_check() {
  log_info "========== 开始预检 =========="

  if [ "$(id -u)" -ne 0 ]; then
    log_error "必须以 root 用户运行此脚本"
    exit 1
  fi

  if [ ! -f /etc/openwrt_release ]; then
    log_error "未检测到 OpenWrt 系统"
    exit 1
  fi

  if ! grep -q "23.05" /etc/openwrt_release 2>/dev/null; then
    log_warn "当前系统不一定是 OpenWrt 23.05（继续执行）"
  fi

  if ! ip link show "$WG_IFACE" >/dev/null 2>&1; then
    log_error "WireGuard 接口 $WG_IFACE 不存在"
    exit 1
  fi

  if ip link show "$WG_IFACE" | grep -qE "<.*UP.*>"; then
    log_success "WireGuard 接口 $WG_IFACE 状态正常"
  else
    log_error "WireGuard 接口 $WG_IFACE 未启动（接口标志位无 UP）"
    exit 1
  fi

  if ! ip addr show "$LAN_IFACE" 2>/dev/null | grep -q "$SIDECAR_IP"; then
    log_warn "未在 $LAN_IFACE 上检测到 $SIDECAR_IP（dnsmasq 监听可能失败）"
    log_warn "建议先给旁路由设置静态 IP: $SIDECAR_IP"
  else
    log_success "检测到旁路由稳定 IP: $SIDECAR_IP"
  fi

  if ! command -v nft >/dev/null 2>&1; then
    log_error "nftables 未安装"
    exit 1
  fi

  if ! lsmod | grep -q "nft_tproxy"; then
    log_info "正在加载 nft_tproxy 内核模块..."
    modprobe nft_tproxy 2>/dev/null || {
      log_error "nft_tproxy 模块加载失败"
      exit 1
    }
    log_success "nft_tproxy 模块加载成功"
  fi

  log_success "预检通过"
}

# ========== 备份函数 ==========

backup_configs() {
  log_info "========== 开始备份现有配置 =========="

  mkdir -p "$BACKUP_DIR"

  nft list table inet xray_tproxy >/dev/null 2>&1 && nft list table inet xray_tproxy >"$BACKUP_DIR/nftables_xray_tproxy.nft" 2>/dev/null || true
  [ -f /etc/nftables.xray_tproxy.nft ] && cp /etc/nftables.xray_tproxy.nft "$BACKUP_DIR/" 2>/dev/null || true

  [ -d /etc/xray ] && cp -r /etc/xray "$BACKUP_DIR/" 2>/dev/null || true
  [ -f /etc/init.d/splittunnel-xray ] && cp /etc/init.d/splittunnel-xray "$BACKUP_DIR/" 2>/dev/null || true

  [ -d /etc/dnsmasq.d ] && cp -r /etc/dnsmasq.d "$BACKUP_DIR/" 2>/dev/null || true

  ip rule >"$BACKUP_DIR/ip_rules.txt" 2>/dev/null || true
  ip route show table "$TABLE_TPROXY" >"$BACKUP_DIR/table_${TABLE_TPROXY}.txt" 2>/dev/null || true
  ip route show table "$TABLE_WG" >"$BACKUP_DIR/table_${TABLE_WG}.txt" 2>/dev/null || true

  [ -d "$SPLITTUNNEL_DIR" ] && cp -r "$SPLITTUNNEL_DIR" "$BACKUP_DIR/splittunnel_old" 2>/dev/null || true

  log_success "备份完成，备份目录: $BACKUP_DIR"
}

# ========== 回滚函数（尽力而为） ==========

rollback() {
  log_info "========== 开始回滚操作 =========="

  [ -d "$BACKUP_DIR" ] || { log_error "备份目录不存在，无法回滚"; return 1; }

  # nft
  if [ -f "$BACKUP_DIR/nftables_xray_tproxy.nft" ]; then
    nft delete table inet xray_tproxy 2>/dev/null || true
    nft -f "$BACKUP_DIR/nftables_xray_tproxy.nft" 2>/dev/null || true
  else
    nft delete table inet xray_tproxy 2>/dev/null || true
  fi

  # xray
  if [ -d "$BACKUP_DIR/xray" ]; then
    rm -rf /etc/xray
    cp -r "$BACKUP_DIR/xray" /etc/xray 2>/dev/null || true
  fi

  # dnsmasq.d
  if [ -d "$BACKUP_DIR/dnsmasq.d" ]; then
    rm -rf /etc/dnsmasq.d
    cp -r "$BACKUP_DIR/dnsmasq.d" /etc/dnsmasq.d 2>/dev/null || true
  fi

  /etc/init.d/firewall reload 2>/dev/null || true
  /etc/init.d/dnsmasq restart 2>/dev/null || true
  /etc/init.d/splittunnel-xray stop 2>/dev/null || true

  log_success "回滚完成（若仍异常，请手工检查）"
}

# ========== 安装依赖 ==========

install_dependencies() {
  log_info "========== 检查并安装依赖包 =========="

  log_info "正在更新 opkg 包列表..."
  if opkg update 2>&1 | tee -a "$LOG_FILE"; then
    log_success "包列表更新成功"
  else
    log_warn "包列表更新失败，将使用本地缓存"
  fi

  # 基础必需
  PKGS="dnsmasq-full xray-core kmod-nft-tproxy ip-full curl ca-bundle wget-ssl"

  for pkg in $PKGS; do
    if opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
      log_info "$pkg 已安装，跳过"
    else
      log_info "正在安装 $pkg..."
      opkg install "$pkg" 2>&1 | tee -a "$LOG_FILE"
      log_success "$pkg 安装成功"
    fi
  done

  # BBR（允许失败不影响主流程）
  if opkg list-installed 2>/dev/null | grep -q "^kmod-tcp-bbr "; then
    log_info "kmod-tcp-bbr 已安装，跳过"
  else
    log_info "正在安装 kmod-tcp-bbr（允许失败）..."
    opkg install kmod-tcp-bbr 2>&1 | tee -a "$LOG_FILE" || log_warn "kmod-tcp-bbr 安装失败（可能内核/仓库不支持）"
  fi

  if opkg list-installed 2>/dev/null | grep -q "^kmod-sched-fq "; then
    log_info "kmod-sched-fq 已安装，跳过"
  else
    log_info "正在安装 kmod-sched-fq（允许失败）..."
    opkg install kmod-sched-fq 2>&1 | tee -a "$LOG_FILE" || log_warn "kmod-sched-fq 安装失败（可能已内置/仓库无此包）"
  fi

  log_success "依赖包检查完成"
}

# ========== 配置 sysctl（TPROXY 必需） ==========

apply_sysctl() {
  log_info "========== 配置 TPROXY 必需 sysctl =========="

  mkdir -p /etc/sysctl.d

  cat >/etc/sysctl.d/97-splittunnel-tproxy.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.default.route_localnet=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF

  sysctl -p /etc/sysctl.d/97-splittunnel-tproxy.conf 2>&1 | tee -a "$LOG_FILE" || true
  sysctl net.ipv4.ip_forward net.ipv4.conf.all.route_localnet net.ipv4.conf.all.rp_filter 2>/dev/null | tee -a "$LOG_FILE" || true

  log_success "sysctl 配置完成"
}

# ========== 启用 BBR（TCP） ==========

enable_bbr() {
  log_info "========== 启用 Google BBR（TCP） =========="

  # 尝试加载模块（不存在就忽略）
  modprobe tcp_bbr 2>/dev/null || true
  modprobe sch_fq  2>/dev/null || true

  cat >/etc/sysctl.d/98-splittunnel-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

  sysctl -p /etc/sysctl.d/98-splittunnel-bbr.conf 2>&1 | tee -a "$LOG_FILE" || true

  CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '')"
  QDISC="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo '')"

  if [ "$CC" = "bbr" ] && [ "$QDISC" = "fq" ]; then
    log_success "✓ BBR 已启用（tcp_congestion_control=bbr, default_qdisc=fq）"
  else
    log_warn "⚠ BBR 未生效：tcp_congestion_control=$CC, default_qdisc=$QDISC"
    log_warn "  可能原因：内核未编译 BBR / 模块不存在 / 仓库无 kmod-tcp-bbr"
  fi
}

# ========== 下载 CN IP（优先走 wg0） ==========

download_cnip() {
  log_info "========== 下载 CN IP 数据 =========="

  mkdir -p "$SPLITTUNNEL_DIR/ipset"

  CNIP_FILE="$SPLITTUNNEL_DIR/ipset/cn4.txt"
  : >"$CNIP_FILE"

  log_info "优先通过 $WG_IFACE 下载: $CNIP_URL"
  if curl -4 --interface "$WG_IFACE" -fsSL --connect-timeout 10 --max-time 30 "$CNIP_URL" -o "$CNIP_FILE" 2>&1 | tee -a "$LOG_FILE"; then
    :
  else
    log_warn "wg0 下载失败，回落普通下载..."
    curl -4 -fsSL --connect-timeout 10 --max-time 30 "$CNIP_URL" -o "$CNIP_FILE" 2>&1 | tee -a "$LOG_FILE" || true
  fi

  if [ ! -s "$CNIP_FILE" ]; then
    log_error "CNIP 文件为空（下载失败或被拦截）"
    return 1
  fi

  CNIP_COUNT="$(wc -l <"$CNIP_FILE" 2>/dev/null || echo 0)"
  if [ "$CNIP_COUNT" -lt 1000 ]; then
    log_error "CNIP 数据异常，仅 $CNIP_COUNT 条"
    return 1
  fi

  log_success "CN IP 下载完成，共 $CNIP_COUNT 条"
}

# ========== 生成 CN 集合加载文件 ==========

generate_cnip_nft() {
  log_info "========== 生成 nftables CN 集合加载文件 =========="

  CNIP_TXT="$SPLITTUNNEL_DIR/ipset/cn4.txt"
  CNIP_NFT="$SPLITTUNNEL_DIR/ipset/cn4.nft"

  cat >"$CNIP_NFT" <<'EOF'
#!/usr/sbin/nft -f
# load elements into inet xray_tproxy set_cn4
# NOTE: set_cn4 must exist before loading.

flush set inet xray_tproxy set_cn4
add element inet xray_tproxy set_cn4 {
EOF

  awk '{print "  "$1","}' "$CNIP_TXT" >>"$CNIP_NFT"
  echo "}" >>"$CNIP_NFT"

  chmod +x "$CNIP_NFT"
  log_success "CN 集合加载文件生成完成: $CNIP_NFT"
}

# ========== 部署 nftables（fw4 include 顶层注入） ==========

deploy_nftables() {
  log_info "========== 部署 nftables 规则 =========="

  NFT_RULESET="/etc/nftables.xray_tproxy.nft"

  cat >"$NFT_RULESET" <<EOF
# SplitTunnel nftables ruleset (fw4 include ruleset-pre)
table inet xray_tproxy {
  set set_cn4 {
    type ipv4_addr
    flags interval
    comment "CN_IP_SET"
  }

  chain prerouting_mangle {
    type filter hook prerouting priority mangle; policy accept;

    meta l4proto != { tcp, udp } return
    ip saddr != $LAN_SUBNET return

    # bypass main router & sidecar itself
    ip daddr { $MAIN_ROUTER_IP, $SIDECAR_IP } return

    # CN bypass first (IP split as main strategy)
    ip daddr @set_cn4 return

    # RFC1918 / local / multicast etc bypass
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 } return

    # TPROXY non-CN
    meta l4proto tcp tproxy ip to 127.0.0.1:$XRAY_TPROXY_PORT meta mark set $XRAY_TPROXY_MARK counter comment "TPROXY_TCP"
    meta l4proto udp tproxy ip to 127.0.0.1:$XRAY_TPROXY_PORT meta mark set $XRAY_TPROXY_MARK counter comment "TPROXY_UDP"
  }
}
EOF

  log_success "已写入 nft ruleset: $NFT_RULESET"

  # fw4 include（顶层注入）
  log_info "配置 firewall include（ruleset-pre 顶层注入）..."
  uci -q delete firewall.xray_tproxy_include || true
  uci set firewall.xray_tproxy_include="include"
  uci set firewall.xray_tproxy_include.type="nftables"
  uci set firewall.xray_tproxy_include.path="$NFT_RULESET"
  uci set firewall.xray_tproxy_include.position="ruleset-pre"
  uci commit firewall

  # reload firewall 会 flush ruleset 并重新加载（避免重复规则）
  log_info "重载 firewall（使 nft 生效）..."
  /etc/init.d/firewall reload 2>&1 | tee -a "$LOG_FILE" || true

  if nft list table inet xray_tproxy >/dev/null 2>&1; then
    log_success "nftables table 已加载: inet xray_tproxy"
  else
    log_error "nftables table 未加载（检查 fw4 include / 语法）"
    return 1
  fi

  log_info "加载 CN IP 集合（会先 flush set）..."
  nft -f "$SPLITTUNNEL_DIR/ipset/cn4.nft" 2>&1 | tee -a "$LOG_FILE"

  CN_COUNT="$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -o '[0-9.]\+/[0-9]\+' | wc -l 2>/dev/null || echo 0)"
  if [ "$CN_COUNT" -lt 1000 ]; then
    log_error "CN set 元素数量异常: $CN_COUNT"
    return 1
  fi

  log_success "nftables 部署完成，CN 集合 $CN_COUNT 条"
}

# ========== 部署 Xray（单文件 config.json + procd 服务） ==========

deploy_xray() {
  log_info "========== 部署 Xray 配置 =========="

  mkdir -p /etc/xray

  # mark 0x2 -> decimal for sockopt.mark
  WG_MARK_DEC="$(printf "%d" "$XRAY_WG_MARK" 2>/dev/null || echo 2)"

  # 生成单文件配置（避免 includes/空规则问题）
  cat >/etc/xray/config.json <<EOF
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
      "settings": {
        "network": "tcp,udp",
        "followRedirect": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "metadataOnly": false
      },
      "streamSettings": {
        "sockopt": {
          "tproxy": "tproxy",
          "mark": 255
        }
      }
    },
    {
      "tag": "dns_in",
      "protocol": "dokodemo-door",
      "listen": "127.0.0.1",
      "port": $XRAY_DNS_PORT,
      "settings": {
        "address": "1.1.1.1",
        "port": 53,
        "network": "udp"
      }
    }
  ],

  "outbounds": [
    {
      "tag": "wg0_out",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIP" },
      "streamSettings": {
        "sockopt": { "mark": $WG_MARK_DEC }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIP" }
    }
  ],

  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["dns_in"],
        "outboundTag": "wg0_out"
      },

      {
        "type": "field",
        "inboundTag": ["tproxy_in"],
        "domain": [
$(echo "$FORCE_WG_DOMAINS" | sed '/^\s*$/d' | sed 's/"/\\"/g' | awk '{printf "          \"%s\",\n",$0}')
          "domain:__end__"
        ],
        "outboundTag": "wg0_out"
      },

      {
        "type": "field",
        "inboundTag": ["tproxy_in"],
        "domain": ["geosite:cn"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "inboundTag": ["tproxy_in"],
        "ip": ["geoip:cn", "geoip:private"],
        "outboundTag": "direct"
      },

      {
        "type": "field",
        "inboundTag": ["tproxy_in"],
        "outboundTag": "wg0_out"
      }
    ]
  }
}
EOF

  # 把 domain list 末尾的占位项去掉（避免空数组/末尾逗号问题）
  sed -i 's/"domain:__end__"//; s/,\s*]/]/' /etc/xray/config.json 2>/dev/null || true

  log_info "测试 Xray 配置..."
  if xray run -test -config /etc/xray/config.json 2>&1 | tee -a "$LOG_FILE"; then
    log_success "Xray 配置测试通过"
  else
    log_error "Xray 配置测试失败（请看上方输出）"
    return 1
  fi

  log_info "========== 部署 Xray procd 服务 : splittunnel-xray =========="

  cat >/etc/init.d/splittunnel-xray <<'EOF'
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

start_service() {
  procd_open_instance
  procd_set_param command /usr/bin/xray run -config /etc/xray/config.json
  procd_set_param respawn 3600 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_set_param user root
  procd_close_instance
}
EOF
  chmod +x /etc/init.d/splittunnel-xray

  /etc/init.d/splittunnel-xray enable 2>/dev/null || true
  /etc/init.d/splittunnel-xray restart 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  if ss -lntp 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT"; then
    log_success "✓ Xray TCP $XRAY_TPROXY_PORT 监听"
  else
    log_warn "⚠ Xray TCP $XRAY_TPROXY_PORT 未监听（稍后自检再看）"
  fi
  if ss -lnup 2>/dev/null | grep -q ":$XRAY_DNS_PORT"; then
    log_success "✓ Xray UDP $XRAY_DNS_PORT 监听"
  else
    log_warn "⚠ Xray UDP $XRAY_DNS_PORT 未监听（稍后自检再看）"
  fi
}

# ========== 部署 dnsmasq（最小化 split.conf，避免重复/冲突） ==========

deploy_dnsmasq() {
  log_info "========== 写入 /etc/dnsmasq.d/split.conf =========="

  mkdir -p /etc/dnsmasq.d

  # 最小化：只写 server 规则，避免与 OpenWrt 自动生成项重复（bind-dynamic/cache-size/no-resolv/strict-order等）
  cat >/etc/dnsmasq.d/split.conf <<EOF
# splittunnel dns split (MINIMAL)
# default forward to xray dns
server=127.0.0.1#$XRAY_DNS_PORT

# CN common domains -> AliDNS (direct)
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

# listen on sidecar ip (optional; if IP not present, dnsmasq may fail)
listen-address=$SIDECAR_IP
EOF

  log_success "split.conf 已写入（最小化）"
}

# ========== 配置策略路由 ==========

configure_policy_routing() {
  log_info "========== 配置策略路由 =========="

  # 清理旧规则
  ip rule del fwmark "$XRAY_TPROXY_MARK" table "$TABLE_TPROXY" 2>/dev/null || true
  ip rule del fwmark "$XRAY_WG_MARK" table "$TABLE_WG" 2>/dev/null || true

  # 规则：tproxy 流量回环交给本机 socket；wg mark 走 wg table
  ip rule add fwmark "$XRAY_TPROXY_MARK" table "$TABLE_TPROXY"
  ip rule add fwmark "$XRAY_WG_MARK" table "$TABLE_WG"

  ip route flush table "$TABLE_TPROXY" 2>/dev/null || true
  ip route add local default dev lo table "$TABLE_TPROXY"

  ip route flush table "$TABLE_WG" 2>/dev/null || true
  ip route add default dev "$WG_IFACE" table "$TABLE_WG"

  # 持久化（接口 up 时补齐）
  mkdir -p /etc/hotplug.d/iface
  cat >/etc/hotplug.d/iface/99-splittunnel-routes <<EOF
#!/bin/sh
[ "\$ACTION" = "ifup" ] || exit 0
case "\$INTERFACE" in
  $LAN_IFACE|lan|br-lan)
    ip rule add fwmark $XRAY_TPROXY_MARK table $TABLE_TPROXY 2>/dev/null || true
    ip rule add fwmark $XRAY_WG_MARK table $TABLE_WG 2>/dev/null || true
    ip route add local default dev lo table $TABLE_TPROXY 2>/dev/null || true
    ip route add default dev $WG_IFACE table $TABLE_WG 2>/dev/null || true
    ;;
esac
EOF
  chmod +x /etc/hotplug.d/iface/99-splittunnel-routes

  log_success "策略路由配置完成"
}

# ========== 重启服务（尽量不报错） ==========

restart_services() {
  log_info "========== 重启相关服务 =========="

  /etc/init.d/network reload 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1
  /etc/init.d/firewall reload 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  /etc/init.d/splittunnel-xray restart 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  /etc/init.d/dnsmasq restart 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  log_success "服务重启完成"
}

# ========== 自检脚本 ==========

generate_selfcheck_script() {
  log_info "========== 生成自检脚本 =========="

  cat >/root/selfcheck_splittunnel.sh <<EOF
#!/bin/sh
echo "========== SplitTunnel Self-Check =========="

echo "[1] wg0:"
ip link show $WG_IFACE 2>/dev/null | sed -n '1,2p' || echo "  ✗ $WG_IFACE missing"
wg show $WG_IFACE 2>/dev/null | sed -n '1,20p' || true

echo "[2] nft:"
nft list table inet xray_tproxy >/dev/null 2>&1 && echo "  ✓ table inet xray_tproxy OK" || echo "  ✗ table missing"
CN=\$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -o '[0-9.]\+/[0-9]\+' | wc -l 2>/dev/null)
echo "  CN set entries: \$CN"
nft -a list chain inet xray_tproxy prerouting_mangle 2>/dev/null | sed -n '1,120p' || true

echo "[3] xray:"
pidof xray >/dev/null 2>&1 && echo "  ✓ xray running" || echo "  ✗ xray not running"
ss -lntp 2>/dev/null | grep -q ':$XRAY_TPROXY_PORT' && echo "  ✓ TCP $XRAY_TPROXY_PORT listening" || echo "  ✗ TCP $XRAY_TPROXY_PORT not listening"
ss -lnup 2>/dev/null | grep -q ':$XRAY_DNS_PORT' && echo "  ✓ UDP $XRAY_DNS_PORT listening" || echo "  ✗ UDP $XRAY_DNS_PORT not listening"
[ -s /tmp/xray_error.log ] && { echo "  xray_error.log:"; tail -n 30 /tmp/xray_error.log; } || true

echo "[4] policy routing:"
ip rule | grep -q "fwmark $XRAY_TPROXY_MARK.*lookup $TABLE_TPROXY" && echo "  ✓ rule $XRAY_TPROXY_MARK -> $TABLE_TPROXY" || echo "  ✗ rule missing"
ip rule | grep -q "fwmark $XRAY_WG_MARK.*lookup $TABLE_WG" && echo "  ✓ rule $XRAY_WG_MARK -> $TABLE_WG" || echo "  ✗ rule missing"
ip route show table $TABLE_WG 2>/dev/null | sed -n '1,10p'

echo "[5] dnsmasq:"
pidof dnsmasq >/dev/null 2>&1 && echo "  ✓ dnsmasq running" || echo "  ✗ dnsmasq not running"
[ -f /etc/dnsmasq.d/split.conf ] && echo "  ✓ /etc/dnsmasq.d/split.conf exists" || echo "  ✗ split.conf missing"

echo ""
echo "NOTE: ICMP(ping) 不代表可用性；分流以 TCP/HTTPS 是否可用为准。"
echo "==========================================="
EOF

  chmod +x /root/selfcheck_splittunnel.sh
  log_success "自检脚本生成: /root/selfcheck_splittunnel.sh"
}

# ========== 部署后自检（简版） ==========

post_deployment_check() {
  log_info "========== 部署后自检 =========="

  ERR=0

  ip addr show "$LAN_IFACE" 2>/dev/null | grep -q "$SIDECAR_IP" \
    && log_success "✓ 稳定 IP 存在：$SIDECAR_IP" \
    || { log_warn "⚠ 未检测到稳定 IP：$SIDECAR_IP（dnsmasq listen-address 可能失败）"; }

  nft list table inet xray_tproxy >/dev/null 2>&1 \
    && log_success "✓ nft table OK（inet xray_tproxy）" \
    || { log_error "✗ nft table 不存在"; ERR=$((ERR+1)); }

  CN_COUNT="$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -o '[0-9.]\+/[0-9]\+' | wc -l 2>/dev/null || echo 0)"
  [ "$CN_COUNT" -gt 1000 ] \
    && log_success "✓ CN set 条数：$CN_COUNT" \
    || { log_error "✗ CN set 异常：$CN_COUNT"; ERR=$((ERR+1)); }

  ss -lntp 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT" \
    && log_success "✓ Xray TCP $XRAY_TPROXY_PORT 监听" \
    || { log_error "✗ Xray TCP $XRAY_TPROXY_PORT 未监听（看 /tmp/xray_error.log）"; ERR=$((ERR+1)); }

  ss -lnup 2>/dev/null | grep -q ":$XRAY_DNS_PORT" \
    && log_success "✓ Xray UDP $XRAY_DNS_PORT 监听" \
    || { log_error "✗ Xray UDP $XRAY_DNS_PORT 未监听（看 /tmp/xray_error.log）"; ERR=$((ERR+1)); }

  pidof dnsmasq >/dev/null 2>&1 \
    && log_success "✓ dnsmasq 已运行" \
    || { log_error "✗ dnsmasq 未运行（看 logread | grep -i dnsmasq）"; ERR=$((ERR+1)); }

  ip rule | grep -q "fwmark $XRAY_TPROXY_MARK.*lookup $TABLE_TPROXY" \
    && log_success "✓ rule: $XRAY_TPROXY_MARK → $TABLE_TPROXY" \
    || { log_error "✗ 缺少 rule: $XRAY_TPROXY_MARK → $TABLE_TPROXY"; ERR=$((ERR+1)); }

  ip rule | grep -q "fwmark $XRAY_WG_MARK.*lookup $TABLE_WG" \
    && log_success "✓ rule: $XRAY_WG_MARK → $TABLE_WG" \
    || { log_error "✗ 缺少 rule: $XRAY_WG_MARK → $TABLE_WG"; ERR=$((ERR+1)); }

  ip route show table "$TABLE_WG" 2>/dev/null | grep -q "dev $WG_IFACE" \
    && log_success "✓ table $TABLE_WG 默认走 $WG_IFACE" \
    || { log_error "✗ table $TABLE_WG 未指向 $WG_IFACE"; ERR=$((ERR+1)); }

  log_info "提示：访问一次国外网站后，TPROXY counter 应增长："
  log_info "  nft -a list chain inet xray_tproxy prerouting_mangle | grep -E 'TPROXY_TCP|TPROXY_UDP'"

  log_info "提示：wg0 transfer 访问国外网站后应增长："
  log_info "  wg show $WG_IFACE"

  log_info "========================================="
  if [ "$ERR" -eq 0 ]; then
    log_success "✓ 自检通过"
  else
    log_error "✗ 自检发现 $ERR 个问题"
    log_error "排查建议："
    log_error "  - logread | grep -i dnsmasq | tail -n 80"
    log_error "  - cat /tmp/xray_error.log"
    log_error "  - nft -a list chain inet xray_tproxy prerouting_mangle"
  fi
  log_info "========================================="
}

# ========== 主函数 ==========

main() {
  log_info "========================================="
  log_info "OpenWrt 23.05 SplitTunnel Deployment (Fix+BBR)"
  log_info "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
  log_info "========================================="

  preflight_check
  backup_configs
  install_dependencies
  apply_sysctl
  enable_bbr

  download_cnip
  generate_cnip_nft
  deploy_nftables

  deploy_xray
  deploy_dnsmasq
  configure_policy_routing

  generate_selfcheck_script
  restart_services
  post_deployment_check

  log_info "========================================="
  log_success "✓ Deployment Complete!"
  log_info "Backup Directory: $BACKUP_DIR"
  log_info "Log File: $LOG_FILE"
  log_info "nft ruleset: $NFT_RULESET"
  log_info "CN loader:   $SPLITTUNNEL_DIR/ipset/cn4.nft"
  log_info "Xray config: /etc/xray/config.json"
  log_info "dnsmasq dir: /etc/dnsmasq.d/"
  log_info "========================================="
  log_info "客户端建议设置："
  log_info "  网关 : $SIDECAR_IP"
  log_info "  DNS  : $SIDECAR_IP"
  log_info "备注：ICMP(ping) 不代表可用性；分流以 TCP/HTTPS 是否可用为准。"
  log_info "========================================="
}

main "$@"
