#!/bin/sh
# ============================================================================
# OpenWrt 23.05 旁路由分流系统 - BusyBox 完全兼容版 v2.1
# 模式: IP 分流为主 + 域名强制走 wg
# 流程: nftables(TPROXY) + Xray(TPROXY+DNS) + dnsmasq
# 兼容: BusyBox sh (完全兼容，无高级语法)
# ============================================================================

set -e

VERSION="2.1"

# -------------------- 默认配置 --------------------
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
LOG_FILE="/root/splittunnel_deploy.log"
CONFIG_FILE="/etc/splittunnel.conf"

CNIP_URL="https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"

# -------------------- 日志函数 --------------------
log_msg() {
    echo "[$1] $(date '+%Y-%m-%d %H:%M:%S') - $2" | tee -a "$LOG_FILE"
}

log_info() {
    log_msg "信息" "$1"
}

log_warn() {
    log_msg "警告" "$1"
}

log_error() {
    log_msg "错误" "$1"
}

log_success() {
    log_msg "成功" "$1"
}

# -------------------- 加载配置 --------------------
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        log_info "加载配置文件: $CONFIG_FILE"
        . "$CONFIG_FILE"
    fi
}

# -------------------- 交互式配置输入 --------------------
interactive_input() {
    echo ""
    echo "========================================="
    echo "SplitTunnel 配置向导 v$VERSION"
    echo "========================================="
    echo "提示: 直接回车使用默认值"
    echo ""
    
    # 检测 WireGuard 接口
    echo "检测到的 WireGuard 接口："
    WG_DETECTED=$(ip link show type wireguard 2>/dev/null | grep -o "^[0-9]*: wg[^:]*" | awk '{print $2}' | head -1)
    if [ -n "$WG_DETECTED" ]; then
        echo "  - $WG_DETECTED"
        WG_IFACE="$WG_DETECTED"
    else
        echo "  (未检测到)"
    fi
    echo ""
    
    # WireGuard 接口
    printf "WireGuard 接口名称 [默认: %s]: " "$WG_IFACE"
    read -r input
    if [ -n "$input" ]; then
        WG_IFACE="$input"
    fi
    
    # LAN 接口
    printf "LAN 接口名称 [默认: %s]: " "$LAN_IFACE"
    read -r input
    if [ -n "$input" ]; then
        LAN_IFACE="$input"
    fi
    
    # LAN 网段
    printf "LAN 网段 [默认: %s]: " "$LAN_SUBNET"
    read -r input
    if [ -n "$input" ]; then
        LAN_SUBNET="$input"
    fi
    
    # 主路由 IP
    printf "主路由 IP [默认: %s]: " "$MAIN_ROUTER_IP"
    read -r input
    if [ -n "$input" ]; then
        MAIN_ROUTER_IP="$input"
    fi
    
    # 旁路由 IP
    printf "旁路由 IP (本机) [默认: %s]: " "$SIDECAR_IP"
    read -r input
    if [ -n "$input" ]; then
        SIDECAR_IP="$input"
    fi
    
    echo ""
    echo "========================================="
    echo "配置确认："
    echo "  WireGuard 接口: $WG_IFACE"
    echo "  LAN 接口:       $LAN_IFACE"
    echo "  LAN 网段:       $LAN_SUBNET"
    echo "  主路由 IP:      $MAIN_ROUTER_IP"
    echo "  旁路由 IP:      $SIDECAR_IP"
    echo "========================================="
    echo ""
    
    printf "确认以上配置? [Y/n]: "
    read -r confirm
    if [ "$confirm" = "n" ] || [ "$confirm" = "N" ]; then
        echo "已取消部署"
        exit 0
    fi
    
    # 询问是否保存配置
    printf "保存配置到 %s? [Y/n]: " "$CONFIG_FILE"
    read -r save_cfg
    if [ "$save_cfg" != "n" ] && [ "$save_cfg" != "N" ]; then
        save_config
    fi
    
    echo ""
}

# -------------------- 保存配置到文件 --------------------
save_config() {
    log_info "保存配置到: $CONFIG_FILE"
    
    cat >"$CONFIG_FILE" <<SAVEEOF
# SplitTunnel 配置文件
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

LAN_SUBNET="$LAN_SUBNET"
MAIN_ROUTER_IP="$MAIN_ROUTER_IP"
SIDECAR_IP="$SIDECAR_IP"
LAN_IFACE="$LAN_IFACE"
WG_IFACE="$WG_IFACE"

XRAY_TPROXY_PORT="$XRAY_TPROXY_PORT"
XRAY_DNS_PORT="$XRAY_DNS_PORT"

XRAY_TPROXY_MARK="$XRAY_TPROXY_MARK"
XRAY_WG_MARK="$XRAY_WG_MARK"

TABLE_TPROXY="$TABLE_TPROXY"
TABLE_WG="$TABLE_WG"

SPLITTUNNEL_DIR="$SPLITTUNNEL_DIR"
CNIP_URL="$CNIP_URL"
SAVEEOF
    
    log_success "配置已保存"
}

# -------------------- 预检 --------------------
preflight_check() {
    log_info "========== 开始预检 =========="

    if [ "$(id -u)" -ne 0 ]; then
        log_error "必须 root 运行"
        exit 1
    fi

    if [ ! -f /etc/openwrt_release ]; then
        log_error "未检测到 OpenWrt"
        exit 1
    fi

    if ! ip link show "$WG_IFACE" >/dev/null 2>&1; then
        log_error "接口 $WG_IFACE 不存在"
        exit 1
    fi

    if ip link show "$WG_IFACE" | grep -qE "<.*UP.*>"; then
        log_success "WireGuard $WG_IFACE 已 UP"
    else
        log_error "WireGuard $WG_IFACE 未 UP"
        exit 1
    fi

    if ! command -v nft >/dev/null 2>&1; then
        log_error "nft 未安装"
        exit 1
    fi

    # 检查并安装 TPROXY 支持
    log_info "检查 TPROXY 支持..."
    
    # 1. 检查模块是否已加载
    if lsmod | grep -qE "nft_tproxy|xt_TPROXY"; then
        log_success "TPROXY 模块已加载"
    else
        # 2. 检查 kmod-nft-tproxy 是否已安装
        if ! opkg list-installed 2>/dev/null | grep -q "^kmod-nft-tproxy "; then
            log_info "kmod-nft-tproxy 未安装，正在安装..."
            opkg update 2>/dev/null || log_warn "opkg update 失败"
            
            if opkg install kmod-nft-tproxy 2>&1 | tee -a "$LOG_FILE"; then
                log_success "kmod-nft-tproxy 安装成功"
            else
                log_warn "kmod-nft-tproxy 安装失败，尝试备选方案..."
                
                # 尝试安装 iptables 的 tproxy 模块
                if opkg install kmod-ipt-tproxy 2>&1 | tee -a "$LOG_FILE"; then
                    log_success "kmod-ipt-tproxy 安装成功"
                else
                    log_warn "TPROXY 模块安装均失败，将测试内核内置支持"
                fi
            fi
        else
            log_info "kmod-nft-tproxy 已安装"
        fi
        
        # 3. 尝试加载模块
        log_info "尝试加载 TPROXY 模块..."
        if modprobe nft_tproxy 2>/dev/null; then
            log_success "nft_tproxy 模块加载成功"
        elif modprobe xt_TPROXY 2>/dev/null; then
            log_success "xt_TPROXY 模块加载成功"
        else
            # 4. 测试内核是否内置支持
            log_warn "模块加载失败，测试内核内置 TPROXY 支持..."
            
            if nft add table inet test_tproxy 2>/dev/null && \
               nft add chain inet test_tproxy test 2>/dev/null && \
               nft add rule inet test_tproxy test meta l4proto tcp tproxy to :12345 2>/dev/null; then
                nft delete table inet test_tproxy 2>/dev/null
                log_success "内核内置 TPROXY 支持（无需模块）"
            else
                nft delete table inet test_tproxy 2>/dev/null || true
                log_error "系统不支持 TPROXY"
                log_error ""
                log_error "可能的原因："
                log_error "  1. 内核版本过旧，不支持 TPROXY"
                log_error "  2. OpenWrt 版本不兼容"
                log_error "  3. 自定义编译的固件缺少 TPROXY 支持"
                log_error ""
                log_error "解决方案："
                log_error "  1. 升级到 OpenWrt 22.03 或更高版本"
                log_error "  2. 使用官方固件而非精简版"
                log_error "  3. 手动编译内核时启用 TPROXY 支持"
                exit 1
            fi
        fi
    fi

    log_success "预检通过"
}

# -------------------- 备份 --------------------
backup_configs() {
    log_info "========== 备份配置 =========="
    mkdir -p "$BACKUP_DIR"

    if nft list table inet xray_tproxy >/dev/null 2>&1; then
        nft list table inet xray_tproxy >"$BACKUP_DIR/nftables_xray_tproxy.nft" 2>/dev/null || true
    fi

    if [ -f /etc/nftables.xray_tproxy.nft ]; then
        cp /etc/nftables.xray_tproxy.nft "$BACKUP_DIR/" 2>/dev/null || true
    fi

    if [ -d /etc/xray ]; then
        cp -r /etc/xray "$BACKUP_DIR/" 2>/dev/null || true
    fi

    if [ -f /etc/init.d/splittunnel-xray ]; then
        cp /etc/init.d/splittunnel-xray "$BACKUP_DIR/" 2>/dev/null || true
    fi

    if [ -d /etc/dnsmasq.d ]; then
        cp -r /etc/dnsmasq.d "$BACKUP_DIR/" 2>/dev/null || true
    fi

    ip rule >"$BACKUP_DIR/ip_rules.txt" 2>/dev/null || true
    ip route show table "$TABLE_TPROXY" >"$BACKUP_DIR/table_${TABLE_TPROXY}.txt" 2>/dev/null || true
    ip route show table "$TABLE_WG" >"$BACKUP_DIR/table_${TABLE_WG}.txt" 2>/dev/null || true

    log_success "备份完成：$BACKUP_DIR"
}

# -------------------- 安装依赖 --------------------
install_dependencies() {
    log_info "========== 检查依赖包 =========="

    log_info "opkg update..."
    opkg update 2>/dev/null || log_warn "opkg update 失败"

    for pkg in xray-core ip-full dnsmasq-full kmod-nft-tproxy curl ca-bundle wget-ssl; do
        if opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
            log_info "$pkg 已安装"
        else
            log_info "安装 $pkg..."
            opkg install "$pkg" 2>&1 | tee -a "$LOG_FILE" || log_warn "$pkg 安装失败"
        fi
    done

    log_success "依赖检查完成"
}

# -------------------- sysctl --------------------
apply_sysctl() {
    log_info "========== 配置 TPROXY sysctl =========="
    mkdir -p /etc/sysctl.d
    
    cat >/etc/sysctl.d/97-splittunnel-tproxy.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.default.route_localnet=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF

    sysctl -p /etc/sysctl.d/97-splittunnel-tproxy.conf 2>/dev/null || true
    log_success "TPROXY sysctl 完成"
}

# -------------------- BBR --------------------
enable_bbr() {
    log_info "========== 启用 Google BBR =========="

    if [ ! -f /proc/sys/net/ipv4/tcp_available_congestion_control ]; then
        log_warn "内核不支持 tcp_congestion_control，跳过 BBR"
        return 0
    fi

    CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    if [ "$CURRENT_CC" = "bbr" ]; then
        log_success "BBR 已启用，跳过配置"
        return 0
    fi

    for pkg in kmod-tcp-bbr kmod-sched-fq; do
        if ! opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
            log_info "安装 $pkg..."
            opkg install "$pkg" 2>&1 | tee -a "$LOG_FILE" || log_warn "$pkg 安装失败"
        fi
    done

    modprobe tcp_bbr 2>/dev/null || true
    modprobe sch_fq 2>/dev/null || true

    mkdir -p /etc/sysctl.d
    cat >/etc/sysctl.d/98-splittunnel-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    sysctl -p /etc/sysctl.d/98-splittunnel-bbr.conf 2>/dev/null || true

    CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    AV=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")

    if echo "$AV" | grep -qw bbr && [ "$CC" = "bbr" ]; then
        log_success "BBR 已启用"
    else
        log_warn "BBR 未生效（内核可能不支持）"
    fi
}

# -------------------- 下载 CNIP --------------------
download_cnip() {
    log_info "========== 下载 CN IP（优先走 wg0） =========="
    mkdir -p "$SPLITTUNNEL_DIR/ipset"
    CNIP_FILE="$SPLITTUNNEL_DIR/ipset/cn4.txt"

    log_info "curl --interface $WG_IFACE ..."
    if curl -4 --interface "$WG_IFACE" -fsSL --connect-timeout 10 --max-time 30 "$CNIP_URL" -o "$CNIP_FILE" 2>>"$LOG_FILE"; then
        :
    else
        log_warn "wg0 下载失败，回落普通下载..."
        curl -4 -fsSL --connect-timeout 10 --max-time 30 "$CNIP_URL" -o "$CNIP_FILE" 2>>"$LOG_FILE" || true
    fi

    if [ ! -s "$CNIP_FILE" ]; then
        log_error "CNIP 文件为空"
        return 1
    fi

    CNIP_COUNT=$(wc -l <"$CNIP_FILE" 2>/dev/null || echo 0)
    if [ "$CNIP_COUNT" -lt 1000 ]; then
        log_error "CNIP 数量异常：$CNIP_COUNT"
        return 1
    fi

    log_success "CNIP 下载完成：$CNIP_COUNT 条"
}

generate_cnip_nft() {
    log_info "========== 生成 CN set 加载文件 =========="
    CNIP_TXT="$SPLITTUNNEL_DIR/ipset/cn4.txt"
    CNIP_NFT="$SPLITTUNNEL_DIR/ipset/cn4.nft"

    cat >"$CNIP_NFT" <<'EOF'
#!/usr/sbin/nft -f
flush set inet xray_tproxy set_cn4
add element inet xray_tproxy set_cn4 {
EOF

    awk '{print "  "$1","}' "$CNIP_TXT" >>"$CNIP_NFT"
    echo "}" >>"$CNIP_NFT"
    chmod +x "$CNIP_NFT"

    log_success "生成完成：$CNIP_NFT"
}

# -------------------- nftables --------------------
deploy_nftables() {
    log_info "========== 部署 nftables =========="
    NFT_RULESET="/etc/nftables.xray_tproxy.nft"

    # 先删除已存在的 table（避免重复规则）
    nft delete table inet xray_tproxy 2>/dev/null || true

    cat >"$NFT_RULESET" <<NFTEOF
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

    ip daddr { $MAIN_ROUTER_IP, $SIDECAR_IP } return
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 } return
    
    ip daddr @set_cn4 return

    meta l4proto tcp tproxy ip to 127.0.0.1:$XRAY_TPROXY_PORT meta mark set $XRAY_TPROXY_MARK counter comment "TPROXY_TCP"
    meta l4proto udp tproxy ip to 127.0.0.1:$XRAY_TPROXY_PORT meta mark set $XRAY_TPROXY_MARK counter comment "TPROXY_UDP"
  }
}
NFTEOF

    uci -q delete firewall.xray_tproxy_include 2>/dev/null || true
    uci set firewall.xray_tproxy_include="include"
    uci set firewall.xray_tproxy_include.type="nftables"
    uci set firewall.xray_tproxy_include.path="$NFT_RULESET"
    uci set firewall.xray_tproxy_include.position="ruleset-pre"
    uci commit firewall

    /etc/init.d/firewall reload 2>/dev/null || true
    sleep 1

    if ! nft list table inet xray_tproxy >/dev/null 2>&1; then
        log_error "nft table 未加载"
        return 1
    fi

    log_info "加载 CN IP 集合..."
    if ! nft -f "$SPLITTUNNEL_DIR/ipset/cn4.nft" >/dev/null 2>&1; then
        log_error "加载 CN set 失败"
        return 1
    fi

    CN_COUNT=$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -o '[0-9.]\+/[0-9]\+' | wc -l 2>/dev/null || echo 0)
    log_success "nftables 部署完成，CN 集合 $CN_COUNT 条"
}

# -------------------- Xray 配置 --------------------
deploy_xray() {
    log_info "========== 部署 Xray 配置 =========="
    mkdir -p /etc/xray

    # 下载 geoip 和 geosite 数据文件
    log_info "检查 Xray 地理位置数据文件..."
    
    GEOIP_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    GEOSITE_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    
    # 检查并下载 geoip.dat
    if [ ! -f /usr/share/xray/geoip.dat ]; then
        log_info "下载 geoip.dat..."
        mkdir -p /usr/share/xray
        if curl -4 --interface "$WG_IFACE" -fsSL -o /usr/share/xray/geoip.dat "$GEOIP_URL" 2>>"$LOG_FILE"; then
            log_success "geoip.dat 下载成功"
        else
            log_warn "通过 wg0 下载失败，尝试普通下载..."
            if curl -4 -fsSL -o /usr/share/xray/geoip.dat "$GEOIP_URL" 2>>"$LOG_FILE"; then
                log_success "geoip.dat 下载成功"
            else
                log_error "geoip.dat 下载失败，将不使用 geoip 规则"
            fi
        fi
    else
        log_info "geoip.dat 已存在"
    fi
    
    # 检查并下载 geosite.dat
    if [ ! -f /usr/share/xray/geosite.dat ]; then
        log_info "下载 geosite.dat..."
        mkdir -p /usr/share/xray
        if curl -4 --interface "$WG_IFACE" -fsSL -o /usr/share/xray/geosite.dat "$GEOSITE_URL" 2>>"$LOG_FILE"; then
            log_success "geosite.dat 下载成功"
        else
            log_warn "通过 wg0 下载失败，尝试普通下载..."
            if curl -4 -fsSL -o /usr/share/xray/geosite.dat "$GEOSITE_URL" 2>>"$LOG_FILE"; then
                log_success "geosite.dat 下载成功"
            else
                log_error "geosite.dat 下载失败，将不使用 geosite 规则"
            fi
        fi
    else
        log_info "geosite.dat 已存在"
    fi

    WG_MARK_DEC=$(printf "%d" "$XRAY_WG_MARK" 2>/dev/null || echo 2)

    # 生成域名列表
    DOMAIN_LIST=$(cat <<'DOMAINLIST'
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
DOMAINLIST
)

    # 转换为 JSON 格式
    TEMP_DOMAIN="/tmp/splittunnel_domains.txt"
    echo "$DOMAIN_LIST" > "$TEMP_DOMAIN"
    
    TOTAL_LINES=$(wc -l < "$TEMP_DOMAIN")
    DOMAIN_JSON=$(awk -v total="$TOTAL_LINES" '{
        gsub(/\\/, "\\\\")
        gsub(/"/, "\\\"")
        if (NR < total) {
            printf "          \"%s\",\n", $0
        } else {
            printf "          \"%s\"\n", $0
        }
    }' "$TEMP_DOMAIN")
    
    rm -f "$TEMP_DOMAIN"

    # 检查是否有 geo 数据文件
    USE_GEOSITE=0
    USE_GEOIP=0
    
    if [ -f /usr/share/xray/geosite.dat ]; then
        USE_GEOSITE=1
        log_info "将使用 geosite 规则"
    else
        log_warn "geosite.dat 不存在，将不使用 geosite 规则"
    fi
    
    if [ -f /usr/share/xray/geoip.dat ]; then
        USE_GEOIP=1
        log_info "将使用 geoip 规则"
    else
        log_warn "geoip.dat 不存在，将不使用 geoip 规则"
    fi

    # 生成 Xray 配置文件
    cat >/etc/xray/config.json <<ENDXRAY
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
          "tproxy": "tproxy"
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
$DOMAIN_JSON
        ],
        "outboundTag": "wg0_out"
      },
ENDXRAY

    # 添加 geosite:cn 规则（如果文件存在）
    if [ "$USE_GEOSITE" -eq 1 ]; then
        cat >>/etc/xray/config.json <<'ENDGEOSITE'

      {
        "type": "field",
        "inboundTag": ["tproxy_in"],
        "domain": ["geosite:cn"],
        "outboundTag": "direct"
      },
ENDGEOSITE
    fi

    # 添加 geoip 规则（如果文件存在）
    if [ "$USE_GEOIP" -eq 1 ]; then
        cat >>/etc/xray/config.json <<'ENDGEOIP'

      {
        "type": "field",
        "inboundTag": ["tproxy_in"],
        "ip": ["geoip:cn", "geoip:private"],
        "outboundTag": "direct"
      },
ENDGEOIP
    fi

    # 添加默认规则
    cat >>/etc/xray/config.json <<'ENDDEFAULT'

      {
        "type": "field",
        "inboundTag": ["tproxy_in"],
        "outboundTag": "wg0_out"
      }
    ]
  }
}
ENDDEFAULT

    log_info "测试 Xray 配置..."
    XRAY_TEST_OUT="/tmp/xray_test.log"
    if xray run -test -config /etc/xray/config.json >"$XRAY_TEST_OUT" 2>&1; then
        cat "$XRAY_TEST_OUT" | tee -a "$LOG_FILE"
        log_success "Xray 配置测试通过"
    else
        cat "$XRAY_TEST_OUT" | tee -a "$LOG_FILE"
        log_error "Xray 配置测试失败"
        rm -f "$XRAY_TEST_OUT"
        return 1
    fi
    rm -f "$XRAY_TEST_OUT"

    log_info "部署 Xray procd 服务..."
    cat >/etc/init.d/splittunnel-xray <<'INITEOF'
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
INITEOF

    chmod +x /etc/init.d/splittunnel-xray
    /etc/init.d/splittunnel-xray enable 2>/dev/null || true
    /etc/init.d/splittunnel-xray restart 2>/dev/null || true
    sleep 2

    if netstat -tulnp 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT.*xray" || \
       ss -tulnp 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT.*xray"; then
        log_success "Xray TCP $XRAY_TPROXY_PORT 监听"
    else
        log_warn "Xray TCP $XRAY_TPROXY_PORT 未监听"
    fi

    if netstat -tulnp 2>/dev/null | grep -q ":$XRAY_DNS_PORT.*xray" || \
       ss -tulnp 2>/dev/null | grep -q ":$XRAY_DNS_PORT.*xray"; then
        log_success "Xray UDP $XRAY_DNS_PORT 监听"
    else
        log_warn "Xray UDP $XRAY_DNS_PORT 未监听"
    fi
}

# -------------------- dnsmasq --------------------
deploy_dnsmasq() {
    log_info "========== 部署 dnsmasq 配置 =========="
    mkdir -p /etc/dnsmasq.d

    cat >/etc/dnsmasq.d/split.conf <<DNSEOF
# splittunnel dns split
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

listen-address=$SIDECAR_IP
DNSEOF

    log_success "dnsmasq 配置完成"
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

    mkdir -p /etc/hotplug.d/iface
    cat >/etc/hotplug.d/iface/99-splittunnel-routes <<HOTEOF
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
HOTEOF

    chmod +x /etc/hotplug.d/iface/99-splittunnel-routes
    log_success "策略路由配置完成"
}

# -------------------- 服务重启 --------------------
restart_services() {
    log_info "========== 重启相关服务 =========="
    
    # 重启网络（可选）
    # /etc/init.d/network reload 2>/dev/null || true
    # sleep 1
    
    # firewall 已在 deploy_nftables 中 reload，这里不重复
    log_info "重启 Xray..."
    /etc/init.d/splittunnel-xray restart 2>/dev/null || true
    sleep 2
    
    log_info "重启 dnsmasq..."
    /etc/init.d/dnsmasq restart 2>/dev/null || true
    sleep 1
    
    log_success "服务重启完成"
}

# -------------------- 自检脚本 --------------------
generate_selfcheck_script() {
    log_info "========== 生成自检脚本 =========="
    cat >/root/selfcheck_splittunnel.sh <<SELFEOF
#!/bin/sh
# 自动加载配置（如果存在）
if [ -f "$CONFIG_FILE" ]; then
    . "$CONFIG_FILE"
else
    # 使用默认值
    WG_IFACE="$WG_IFACE"
    XRAY_TPROXY_PORT="$XRAY_TPROXY_PORT"
    XRAY_DNS_PORT="$XRAY_DNS_PORT"
    XRAY_TPROXY_MARK="$XRAY_TPROXY_MARK"
    XRAY_WG_MARK="$XRAY_WG_MARK"
    TABLE_TPROXY="$TABLE_TPROXY"
    TABLE_WG="$TABLE_WG"
fi

echo "========== SplitTunnel Self-Check =========="
echo "配置: \$WG_IFACE=$WG_IFACE"
echo ""

echo "[1] WireGuard:"
ip link show \$WG_IFACE 2>/dev/null | sed -n '1,2p' || echo "  ✗ \$WG_IFACE missing"
wg show \$WG_IFACE 2>/dev/null | sed -n '1,20p' || true

echo "[2] nftables:"
if nft list table inet xray_tproxy >/dev/null 2>&1; then
    echo "  ✓ table inet xray_tproxy OK"
else
    echo "  ✗ table missing"
fi
CN=\$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -o '[0-9.]\+/[0-9]\+' | wc -l 2>/dev/null)
echo "  CN set entries: \$CN"
nft -a list chain inet xray_tproxy prerouting_mangle 2>/dev/null | sed -n '1,20p' || true

echo "[3] Xray:"
if pidof xray >/dev/null 2>&1; then
    echo "  ✓ xray running"
else
    echo "  ✗ xray not running"
fi

# 使用 netstat 更可靠地检测端口
if netstat -tulnp 2>/dev/null | grep -q ":\$XRAY_TPROXY_PORT.*xray" || \
   ss -tulnp 2>/dev/null | grep -q ":\$XRAY_TPROXY_PORT.*xray"; then
    echo "  ✓ TCP \$XRAY_TPROXY_PORT listening"
else
    echo "  ✗ TCP \$XRAY_TPROXY_PORT not listening"
fi

if netstat -tulnp 2>/dev/null | grep -q ":\$XRAY_DNS_PORT.*xray" || \
   ss -tulnp 2>/dev/null | grep -q ":\$XRAY_DNS_PORT.*xray"; then
    echo "  ✓ UDP \$XRAY_DNS_PORT listening"
else
    echo "  ✗ UDP \$XRAY_DNS_PORT not listening"
fi

if [ -s /tmp/xray_error.log ]; then
    echo "  xray_error.log (last 10 lines):"
    tail -n 10 /tmp/xray_error.log | sed 's/^/    /'
fi

echo "[4] 策略路由:"
if ip rule | grep -q "fwmark \$XRAY_TPROXY_MARK.*lookup \$TABLE_TPROXY"; then
    echo "  ✓ rule \$XRAY_TPROXY_MARK -> \$TABLE_TPROXY"
else
    echo "  ✗ rule missing"
fi

if ip rule | grep -q "fwmark \$XRAY_WG_MARK.*lookup \$TABLE_WG"; then
    echo "  ✓ rule \$XRAY_WG_MARK -> \$TABLE_WG"
else
    echo "  ✗ rule missing"
fi

echo "  table \$TABLE_WG routes:"
ip route show table \$TABLE_WG 2>/dev/null | sed 's/^/    /' | head -5

echo "[5] dnsmasq:"
if pidof dnsmasq >/dev/null 2>&1; then
    echo "  ✓ dnsmasq running"
else
    echo "  ✗ dnsmasq not running"
fi

if [ -f /etc/dnsmasq.d/split.conf ]; then
    echo "  ✓ /etc/dnsmasq.d/split.conf exists"
else
    echo "  ✗ split.conf missing"
fi

echo ""
echo "提示: ICMP(ping) 不代表可用性，以 TCP/HTTPS 为准"
echo "测试: curl -I https://www.google.com"
echo "==========================================="
SELFEOF

    chmod +x /root/selfcheck_splittunnel.sh
    log_success "自检脚本：/root/selfcheck_splittunnel.sh"
}

# -------------------- 部署后检查 --------------------
post_deployment_check() {
    log_info "========== 部署后自检 =========="
    CHECK_ERR=0

    if nft list table inet xray_tproxy >/dev/null 2>&1; then
        log_success "nft table OK"
    else
        log_error "nft table 不存在"
        CHECK_ERR=1
    fi

    CN_COUNT=$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -o '[0-9.]\+/[0-9]\+' | wc -l 2>/dev/null || echo 0)
    if [ "$CN_COUNT" -gt 1000 ]; then
        log_success "CN set：$CN_COUNT 条"
    else
        log_error "CN set 异常：$CN_COUNT"
        CHECK_ERR=1
    fi

    if netstat -tulnp 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT.*xray" || \
       ss -tulnp 2>/dev/null | grep -q ":$XRAY_TPROXY_PORT.*xray"; then
        log_success "Xray TCP 监听"
    else
        log_error "Xray TCP 未监听"
        CHECK_ERR=1
    fi

    if netstat -tulnp 2>/dev/null | grep -q ":$XRAY_DNS_PORT.*xray" || \
       ss -tulnp 2>/dev/null | grep -q ":$XRAY_DNS_PORT.*xray"; then
        log_success "Xray UDP 监听"
    else
        log_error "Xray UDP 未监听"
        CHECK_ERR=1
    fi

    if pidof dnsmasq >/dev/null 2>&1; then
        log_success "dnsmasq 运行"
    else
        log_error "dnsmasq 未运行"
        CHECK_ERR=1
    fi

    if ip rule | grep -q "fwmark $XRAY_TPROXY_MARK.*lookup $TABLE_TPROXY"; then
        log_success "rule: $XRAY_TPROXY_MARK → $TABLE_TPROXY"
    else
        log_error "缺少 rule"
        CHECK_ERR=1
    fi

    if ip rule | grep -q "fwmark $XRAY_WG_MARK.*lookup $TABLE_WG"; then
        log_success "rule: $XRAY_WG_MARK → $TABLE_WG"
    else
        log_error "缺少 rule"
        CHECK_ERR=1
    fi

    if ip route show table "$TABLE_WG" 2>/dev/null | grep -q "dev $WG_IFACE"; then
        log_success "table $TABLE_WG → $WG_IFACE"
    else
        log_error "table $TABLE_WG 路由错误"
        CHECK_ERR=1
    fi

    if [ "$CHECK_ERR" -eq 0 ]; then
        log_success "自检通过"
    else
        log_error "自检发现问题"
    fi
}

# -------------------- 使用说明 --------------------
show_usage() {
    echo "SplitTunnel 部署脚本 v$VERSION"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  (无参数)              交互式部署（推荐首次使用）"
    echo "  --auto               自动部署（使用默认或已保存配置）"
    echo "  --update-cnip        仅更新 CN IP 列表"
    echo "  --health-check       健康检查"
    echo "  -h, --help           显示此帮助"
    echo ""
    echo "示例:"
    echo "  $0                   # 交互式部署（会询问配置）"
    echo "  $0 --auto            # 自动部署（不询问）"
    echo "  $0 --update-cnip     # 更新 CN IP"
    echo "  $0 --health-check    # 检查系统状态"
    echo ""
    echo "配置文件: $CONFIG_FILE"
    echo "日志文件: $LOG_FILE"
    echo ""
}

# -------------------- 增量更新 --------------------
update_cnip_only() {
    log_info "========== 仅更新 CN IP =========="
    load_config
    
    if ! download_cnip; then
        log_error "下载 CN IP 失败"
        return 1
    fi
    
    if ! generate_cnip_nft; then
        log_error "生成 CN nft 失败"
        return 1
    fi
    
    log_info "重新加载 CN IP 集合..."
    if ! nft -f "$SPLITTUNNEL_DIR/ipset/cn4.nft"; then
        log_error "加载 CN set 失败"
        return 1
    fi
    
    CN_COUNT=$(nft list set inet xray_tproxy set_cn4 2>/dev/null | grep -o '[0-9.]\+/[0-9]\+' | wc -l 2>/dev/null || echo 0)
    log_success "CN IP 更新完成：$CN_COUNT 条"
}

# -------------------- 健康检查 --------------------
health_check() {
    log_info "========== 健康检查 =========="
    HEALTH_ERR=0
    
    log_info "测试 WireGuard 连通性..."
    if curl -4 -m 5 --interface "$WG_IFACE" https://1.1.1.1 >/dev/null 2>&1; then
        log_success "WireGuard 连通性正常"
    else
        log_error "WireGuard 无法访问外网"
        HEALTH_ERR=1
    fi
    
    log_info "检查服务状态..."
    if pidof xray >/dev/null 2>&1; then
        log_success "Xray 运行中"
    else
        log_error "Xray 未运行"
        HEALTH_ERR=1
    fi
    
    if pidof dnsmasq >/dev/null 2>&1; then
        log_success "dnsmasq 运行中"
    else
        log_error "dnsmasq 未运行"
        HEALTH_ERR=1
    fi
    
    if [ "$HEALTH_ERR" -eq 0 ]; then
        log_success "健康检查通过"
    else
        log_error "健康检查发现问题"
    fi
}

# -------------------- 完整部署 --------------------
full_deploy() {
    INTERACTIVE_MODE="$1"
    
    log_info "========================================="
    log_info "SplitTunnel 完整部署 v$VERSION"
    log_info "开始时间: $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "========================================="

    # 如果是交互模式，显示配置向导
    if [ "$INTERACTIVE_MODE" = "interactive" ]; then
        interactive_input
    fi

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
    log_success "部署完成!"
    log_info "备份: $BACKUP_DIR"
    log_info "日志: $LOG_FILE"
    log_info "========================================="
    log_info "下一步："
    log_info "  1. 客户端配置: 网关=$SIDECAR_IP  DNS=$SIDECAR_IP"
    log_info "  2. 运行自检: /root/selfcheck_splittunnel.sh"
    log_info "  3. 健康检查: $0 --health-check"
    log_info "========================================="
}

# -------------------- 主入口 --------------------
main() {
    case "${1:-}" in
        -h|--help)
            show_usage
            exit 0
            ;;
        --auto)
            # 自动模式：使用默认或已保存的配置，不询问
            load_config
            full_deploy "auto"
            ;;
        --update-cnip)
            load_config
            update_cnip_only
            ;;
        --health-check)
            load_config
            health_check
            ;;
        "")
            # 无参数：交互模式（推荐首次使用）
            load_config
            full_deploy "interactive"
            ;;
        *)
            log_error "未知选项: $1"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
