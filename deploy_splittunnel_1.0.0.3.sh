#!/bin/sh
# ============================================================================
# OpenWrt 23.05 旁路由分流系统 - 一键部署脚本（修复版）
# 方案：IP 分流为主 + 域名强制走 wg（补丁）
# 组件：nftables(TPROXY) + Xray + dnsmasq
# 兼容：BusyBox sh
# 日期：2026-01-08
# ============================================================================

set -eu

# -------------------- 配置区（按需改） --------------------
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

CNIP_URL="https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"

# “域名强制走 wg（补丁）”：主流国外域名（可自行增删）
FORCE_WG_DOMAINS="
google.com
gstatic.com
googleapis.com
youtube.com
ytimg.com
ggpht.com
github.com
githubusercontent.com
ghcr.io
githubassets.com
githubstatus.com
docker.com
docker.io
cloudflare.com
cloudflare-dns.com
1.1.1.1
openai.com
chatgpt.com
reddit.com
twitter.com
x.com
t.co
telegram.org
t.me
wikipedia.org
wikimedia.org
"

# -------------------- 日志 --------------------
log_info()   { echo "[信息] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_warn()   { echo "[警告] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_error()  { echo "[错误] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }
log_success(){ echo "[成功] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }

cleanup_on_error() {
  log_error "部署过程中发生错误（第 $1 行）"
  log_error "请查看日志：$LOG_FILE"
  exit 1
}
trap 'cleanup_on_error $LINENO' ERR

# -------------------- 预检 --------------------
preflight_check() {
  log_info "========== 开始预检 =========="

  [ "$(id -u)" -eq 0 ] || { log_error "必须以 root 运行"; exit 1; }
  [ -f /etc/openwrt_release ] || { log_error "未检测到 OpenWrt"; exit 1; }

  if ! ip link show "$WG_IFACE" >/dev/null 2>&1; then
    log_error "WireGuard 接口不存在：$WG_IFACE"
    exit 1
  fi

  if ip link show "$WG_IFACE" | grep -qE "<.*UP.*>"; then
    log_success "WireGuard 接口 UP：$WG_IFACE"
  else
    log_error "WireGuard 接口未 UP：$WG_IFACE"
    exit 1
  fi

  command -v nft >/dev/null 2>&1 || { log_error "缺少 nft（nftables）"; exit 1; }
  command -v xray >/dev/null 2>&1 || log_warn "未找到 xray（后续会安装 xray-core）"
  command -v curl >/dev/null 2>&1 || log_warn "未找到 curl（后续会安装）"

  # tproxy 模块
  if ! lsmod 2>/dev/null | grep -q "nft_tproxy"; then
    log_info "加载 nft_tproxy 模块..."
    modprobe nft_tproxy 2>/dev/null || { log_error "nft_tproxy 模块加载失败"; exit 1; }
  fi

  log_success "预检通过"
}

# -------------------- 备份 --------------------
backup_configs() {
  log_info "========== 备份现有配置 =========="
  mkdir -p "$BACKUP_DIR"

  # nft
  nft list table inet xray_tproxy >/dev/null 2>&1 && nft list table inet xray_tproxy >"$BACKUP_DIR/nft_xray_tproxy.txt" 2>/dev/null || true
  # xray
  [ -d /etc/xray ] && cp -r /etc/xray "$BACKUP_DIR/" 2>/dev/null || true
  # dnsmasq.d
  [ -d /etc/dnsmasq.d ] && cp -r /etc/dnsmasq.d "$BACKUP_DIR/" 2>/dev/null || true
  # uci
  uci export dhcp >"$BACKUP_DIR/uci_dhcp.txt" 2>/dev/null || true
  uci export firewall >"$BACKUP_DIR/uci_firewall.txt" 2>/dev/null || true
  # policy routing
  ip rule show >"$BACKUP_DIR/ip_rules.txt" 2>/dev/null || true
  ip route show table "$TABLE_TPROXY" >"$BACKUP_DIR/route_table_${TABLE_TPROXY}.txt" 2>/dev/null || true
  ip route show table "$TABLE_WG" >"$BACKUP_DIR/route_table_${TABLE_WG}.txt" 2>/dev/null || true

  log_success "备份完成：$BACKUP_DIR"
}

# -------------------- 安装依赖 --------------------
install_dependencies() {
  log_info "========== 检查并安装依赖 =========="
  opkg update 2>&1 | tee -a "$LOG_FILE" || log_warn "opkg update 失败，将继续尝试安装"

  PKGS="dnsmasq-full xray-core kmod-nft-tproxy ip-full curl ca-bundle"
  for p in $PKGS; do
    if opkg list-installed 2>/dev/null | grep -q "^${p} "; then
      log_info "$p 已安装，跳过"
    else
      log_info "安装 $p ..."
      opkg install "$p" 2>&1 | tee -a "$LOG_FILE"
      log_success "$p 安装完成"
    fi
  done

  # 确保 /etc/dnsmasq.d 存在（避免 dnsmasq 因 conf-dir 指向不存在目录而崩）
  mkdir -p /etc/dnsmasq.d
  log_success "依赖检查完成"
}

# -------------------- sysctl（TPROXY 必需） --------------------
apply_sysctl() {
  log_info "========== 配置 TPROXY 必需 sysctl =========="
  cat >/etc/sysctl.d/99-splittunnel-tproxy.conf <<EOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.default.route_localnet=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  sysctl -p /etc/sysctl.d/99-splittunnel-tproxy.conf 2>&1 | tee -a "$LOG_FILE" || true
  log_success "sysctl 配置完成"
}

# -------------------- CNIP 下载（优先 wg0） --------------------
download_cnip() {
  log_info "========== 下载 CN IP 数据 =========="
  mkdir -p "$SPLITTUNNEL_DIR/ipset"

  # 先用 wg0 下载（用户诉求：CNIP 下载走 wg0）
  log_info "尝试使用 wg0 下载 CNIP（curl --interface wg0）..."
  if curl -4 --interface "$WG_IFACE" -L --max-time 30 -o "$SPLITTUNNEL_DIR/ipset/cn4.txt" "$CNIP_URL" 2>>"$LOG_FILE"; then
    :
  else
    log_warn "wg0 下载失败，回落普通下载..."
    curl -4 -L --max-time 30 -o "$SPLITTUNNEL_DIR/ipset/cn4.txt" "$CNIP_URL" 2>>"$LOG_FILE" || {
      log_error "CNIP 下载失败"
      exit 1
    }
  fi

  [ -s "$SPLITTUNNEL_DIR/ipset/cn4.txt" ] || { log_error "CNIP 文件为空"; exit 1; }

  CNIP_COUNT="$(wc -l <"$SPLITTUNNEL_DIR/ipset/cn4.txt" 2>/dev/null || echo 0)"
  [ "$CNIP_COUNT" -gt 1000 ] || { log_error "CNIP 数据异常：$CNIP_COUNT 行"; exit 1; }

  log_success "CNIP 下载完成：$CNIP_COUNT 行"
}

# -------------------- 生成 CN 集合加载脚本（nft） --------------------
generate_cnip_loader() {
  log_info "========== 生成 CN 集合加载文件 =========="
  cat >"$SPLITTUNNEL_DIR/ipset/cn4.nft" <<'EOF'
#!/usr/sbin/nft -f
flush set inet xray_tproxy set_cn4
EOF

  # 写入 add element
  echo "add element inet xray_tproxy set_cn4 {" >>"$SPLITTUNNEL_DIR/ipset/cn4.nft"
  awk '{print "  " $1 ","}' "$SPLITTUNNEL_DIR/ipset/cn4.txt" >>"$SPLITTUNNEL_DIR/ipset/cn4.nft"
  echo "}" >>"$SPLITTUNNEL_DIR/ipset/cn4.nft"

  chmod +x "$SPLITTUNNEL_DIR/ipset/cn4.nft"
  log_success "CN loader 已生成：$SPLITTUNNEL_DIR/ipset/cn4.nft"
}

# -------------------- 部署 nftables（TPROXY + CN 绕过） --------------------
deploy_nftables() {
  log_info "========== 部署 nftables 规则 =========="

  cat >/etc/nftables.xray_tproxy.nft <<EOF
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

    # 避免旁路由/主路由互访被 tproxy
    ip daddr { $MAIN_ROUTER_IP, $SIDECAR_IP } return

    # CN IP 直连（IP 分流为主）
    ip daddr @set_cn4 return comment "CN_DIRECT"

    # 私网/保留地址直连
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 } return comment "PRIVATE_DIRECT"

    meta l4proto tcp tproxy ip to 127.0.0.1:$XRAY_TPROXY_PORT meta mark set $XRAY_TPROXY_MARK counter comment "TPROXY_TCP"
    meta l4proto udp tproxy ip to 127.0.0.1:$XRAY_TPROXY_PORT meta mark set $XRAY_TPROXY_MARK counter comment "TPROXY_UDP"
  }
}
EOF

  # 为避免你现在链里出现的“重复规则”，先删旧 table
  nft delete table inet xray_tproxy >/dev/null 2>&1 || true

  # 通过 firewall include 注入（ruleset-pre）
  uci -q delete firewall.xray_tproxy_include || true
  uci set firewall.xray_tproxy_include="include"
  uci set firewall.xray_tproxy_include.type="nftables"
  uci set firewall.xray_tproxy_include.path="/etc/nftables.xray_tproxy.nft"
  uci set firewall.xray_tproxy_include.position="ruleset-pre"
  uci commit firewall

  log_info "重载 firewall 以加载 nft ruleset..."
  /etc/init.d/firewall restart 2>&1 | tee -a "$LOG_FILE"

  nft list table inet xray_tproxy >/dev/null 2>&1 || { log_error "nft table 未加载"; exit 1; }

  log_info "加载 CN set（可能需要一点时间）..."
  nft -f "$SPLITTUNNEL_DIR/ipset/cn4.nft" 2>&1 | tee -a "$LOG_FILE" || { log_error "CN set 加载失败"; exit 1; }

  CN_COUNT="$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | wc -l 2>/dev/null || echo 0)"
  [ "$CN_COUNT" -gt 1000 ] || { log_error "CN set 条数异常：$CN_COUNT"; exit 1; }

  log_success "nftables 部署完成，CN set：$CN_COUNT 条"
}

# -------------------- Xray：强制单文件（避免 conf.d 残留空规则） --------------------
deploy_xray_singlefile() {
  log_info "========== 部署 Xray 配置（单文件，避免 conf.d 残留） =========="

  mkdir -p /etc/xray

  # 备份并移走 conf.d（避免“隐藏坏文件”继续被 includes 读到）
  if [ -d /etc/xray/conf.d ]; then
    mkdir -p "$BACKUP_DIR/xray_conf_d"
    cp -r /etc/xray/conf.d "$BACKUP_DIR/xray_conf_d/" 2>/dev/null || true
    rm -rf /etc/xray/conf.d
    log_info "已移除 /etc/xray/conf.d（已备份到 $BACKUP_DIR/xray_conf_d/）"
  fi

  WG_MARK_DEC="$(printf "%d" "$XRAY_WG_MARK")"

  # 生成 domains 数组 JSON（简单安全：逐行过滤空行与注释）
  FORCE_JSON="$(echo "$FORCE_WG_DOMAINS" | sed 's/#.*$//g' | awk 'NF{print}' | awk '{printf "\"domain:%s\",\n",$0}' | sed '$s/,$//')"
  [ -n "$FORCE_JSON" ] || FORCE_JSON="\"domain:example.com\""

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
        "destOverride": ["http", "tls", "quic"]
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
        "network": "udp",
        "outboundTag": "wg0_out"
      },
      {
        "type": "field",
        "inboundTag": ["tproxy_in"],
        "domain": [
          $FORCE_JSON
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
        "network": "tcp,udp",
        "outboundTag": "wg0_out"
      }
    ]
  }
}
EOF

  log_info "测试 Xray 配置..."
  xray run -test -config /etc/xray/config.json 2>&1 | tee -a "$LOG_FILE" || {
    log_error "Xray 配置测试失败（请看上方输出）"
    exit 1
  }

  # 关闭原生 xray（避免冲突）
  if [ -x /etc/init.d/xray ]; then
    /etc/init.d/xray stop >/dev/null 2>&1 || true
    /etc/init.d/xray disable >/dev/null 2>&1 || true
  fi

  # 安装 splittunnel-xray procd
  cat >/usr/bin/splittunnel-xray-run <<'WRAP'
#!/bin/sh
exec xray run -config /etc/xray/config.json >>/tmp/splittunnel-xray.run.log 2>&1
WRAP
  chmod +x /usr/bin/splittunnel-xray-run

  cat >/etc/init.d/splittunnel-xray <<'INIT'
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
start_service() {
  procd_open_instance
  procd_set_param command /usr/bin/splittunnel-xray-run
  procd_set_param respawn 3600 5 5
  procd_close_instance
}
INIT
  chmod +x /etc/init.d/splittunnel-xray
  /etc/init.d/splittunnel-xray enable >/dev/null 2>&1 || true

  log_success "Xray 单文件配置部署完成"
}

# -------------------- dnsmasq：只写 server 行，避免 bind 冲突/重复关键字 --------------------
deploy_dnsmasq() {
  log_info "========== 部署 dnsmasq split.conf（最小化） =========="
  mkdir -p /etc/dnsmasq.d

  # 重要：不要写 bind-interfaces（会与 OpenWrt 的 bind-dynamic 冲突）
  # 重要：不要重复写 no-resolv/strict-order/cache-size（避免 illegal repeated keyword）
  cat >/etc/dnsmasq.d/split.conf <<EOF
# splittunnel dns (minimal)
# default forward to xray dns
server=127.0.0.1#$XRAY_DNS_PORT

# China domains direct (optional)
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
EOF

  log_success "dnsmasq split.conf 已写入：/etc/dnsmasq.d/split.conf"
}

# -------------------- 策略路由 --------------------
configure_policy_routing() {
  log_info "========== 配置策略路由 =========="

  ip rule del fwmark "$XRAY_TPROXY_MARK" table "$TABLE_TPROXY" 2>/dev/null || true
  ip rule del fwmark "$XRAY_WG_MARK" table "$TABLE_WG" 2>/dev/null || true

  ip rule add fwmark "$XRAY_TPROXY_MARK" table "$TABLE_TPROXY"
  ip rule add fwmark "$XRAY_WG_MARK" table "$TABLE_WG"

  ip route flush table "$TABLE_TPROXY" 2>/dev/null || true
  ip route add local default dev lo table "$TABLE_TPROXY"

  ip route flush table "$TABLE_WG" 2>/dev/null || true
  ip route add default dev "$WG_IFACE" table "$TABLE_WG"

  # 持久化（ifup 时恢复）
  mkdir -p /etc/hotplug.d/iface
  cat >/etc/hotplug.d/iface/99-splittunnel-routes <<EOF
#!/bin/sh
[ "\$ACTION" = "ifup" ] || exit 0
case "\$INTERFACE" in
  lan|br-lan)
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

# -------------------- 重启服务 --------------------
restart_services() {
  log_info "========== 重启相关服务 =========="

  /etc/init.d/network reload 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  /etc/init.d/firewall restart 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  /etc/init.d/splittunnel-xray restart >/dev/null 2>&1 || true
  sleep 1

  /etc/init.d/dnsmasq restart 2>&1 | tee -a "$LOG_FILE" || true
  sleep 1

  log_success "服务重启完成"
}

# -------------------- 自检 --------------------
post_check() {
  log_info "========== 部署后自检 =========="

  ERR=0

  ip addr show "$LAN_IFACE" 2>/dev/null | grep -q "$SIDECAR_IP" && log_success "✓ 稳定 IP 存在：$SIDECAR_IP" || { log_warn "⚠ 未在 $LAN_IFACE 上发现 $SIDECAR_IP（如果你是手工配的 IP 请确认）"; }

  nft list table inet xray_tproxy >/dev/null 2>&1 && log_success "✓ nft table OK（inet xray_tproxy）" || { log_error "✗ nft table 缺失"; ERR=$((ERR+1)); }

  CN_COUNT="$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | wc -l 2>/dev/null || echo 0)"
  [ "$CN_COUNT" -gt 1000 ] && log_success "✓ CN set 条数：$CN_COUNT" || { log_error "✗ CN set 异常：$CN_COUNT"; ERR=$((ERR+1)); }

  ss -lntp 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT" && log_success "✓ Xray TCP $XRAY_TPROXY_PORT 监听" || { log_error "✗ Xray TCP $XRAY_TPROXY_PORT 未监听（看 /tmp/splittunnel-xray.run.log 或 /tmp/xray_error.log）"; ERR=$((ERR+1)); }
  ss -lnup 2>/dev/null | grep -q ":$XRAY_DNS_PORT" && log_success "✓ Xray UDP $XRAY_DNS_PORT 监听" || { log_error "✗ Xray UDP $XRAY_DNS_PORT 未监听（看 /tmp/splittunnel-xray.run.log 或 /tmp/xray_error.log）"; ERR=$((ERR+1)); }

  pidof dnsmasq >/dev/null 2>&1 && log_success "✓ dnsmasq 运行中" || { log_error "✗ dnsmasq 未运行（常见原因：配置冲突/目录不存在）"; ERR=$((ERR+1)); }

  ip rule | grep -q "fwmark $XRAY_TPROXY_MARK lookup $TABLE_TPROXY" && log_success "✓ rule: $XRAY_TPROXY_MARK → $TABLE_TPROXY" || { log_error "✗ 缺少 TPROXY ip rule"; ERR=$((ERR+1)); }
  ip rule | grep -q "fwmark $XRAY_WG_MARK lookup $TABLE_WG" && log_success "✓ rule: $XRAY_WG_MARK → $TABLE_WG" || { log_error "✗ 缺少 WG ip rule"; ERR=$((ERR+1)); }

  ip route show table "$TABLE_WG" 2>/dev/null | grep -q "default dev $WG_IFACE" && log_success "✓ table $TABLE_WG 默认走 $WG_IFACE" || { log_error "✗ table $TABLE_WG 缺少默认路由"; ERR=$((ERR+1)); }

  log_info "提示：访问一次国外 HTTPS 网站后，TPROXY counter 应增长："
  nft -a list chain inet xray_tproxy prerouting_mangle 2>/dev/null | grep -E 'TPROXY_(TCP|UDP)' | tail -n 4 || true

  if [ "$ERR" -eq 0 ]; then
    log_success "✓ 自检通过"
    log_info "备注：ICMP(ping) 不代表可用性；本方案只处理 TCP/UDP（HTTPS/QUIC/DNS）。"
  else
    log_error "✗ 自检发现 $ERR 个问题"
    log_error "排查建议："
    log_error "  - cat /tmp/xray_error.log"
    log_error "  - tail -n 200 /tmp/splittunnel-xray.run.log"
    log_error "  - logread | grep -i dnsmasq | tail -n 80"
  fi
}

# -------------------- 主流程 --------------------
main() {
  log_info "========================================="
  log_info "OpenWrt Split Tunnel Deployment (Fixed)"
  log_info "Start: $(date '+%Y-%m-%d %H:%M:%S')"
  log_info "========================================="

  preflight_check
  backup_configs
  install_dependencies
  apply_sysctl
  download_cnip
  generate_cnip_loader
  deploy_nftables
  deploy_xray_singlefile
  deploy_dnsmasq
  configure_policy_routing
  restart_services
  post_check

  log_info "========================================="
  log_success "✓ Deployment Complete!"
  log_info "Backup Directory: $BACKUP_DIR"
  log_info "Log File: $LOG_FILE"
  log_info "nft ruleset: /etc/nftables.xray_tproxy.nft"
  log_info "CN loader:   $SPLITTUNNEL_DIR/ipset/cn4.nft"
  log_info "Xray config: /etc/xray/config.json"
  log_info "dnsmasq dir: /etc/dnsmasq.d/"
  log_info "========================================="
  log_info "客户端建议设置："
  log_info "  网关: $SIDECAR_IP"
  log_info "  DNS : $SIDECAR_IP"
  log_info "========================================="
}

main "$@"
