#!/bin/sh
# /root/deploy_splittunnel.sh
# OpenWrt 23.05 旁路由分流：nftables + Xray-core + WireGuard(wg0) + dnsmasq-full
# 当前阶段：无代理节点；非 CN -> wg0；CN 必须在 nftables 层硬绕过（不进 Xray）
# 兼容 BusyBox sh：不使用数组/[[ ]]/bash 特性
# 日志：/root/deploy_splittunnel.log

#####################################
# 变量集中区（强制预填）
#####################################
LAN_SUBNET="192.168.88.0/24"
MAIN_ROUTER_IP="192.168.88.1"
SIDECAR_IP="192.168.88.200"
WG_IFACE="wg0"

# LAN 接口：可留空让脚本自动探测；探测不到默认 br-lan
LAN_IFACE=""

# 端口
TPROXY_PORT="12345"
XRAY_DNS_PORT="5353"

# nft 命名（规范化）
NFT_TABLE_FAMILY="inet"
NFT_TABLE_NAME="xray_tproxy"
NFT_CHAIN_PREROUTING="prerouting_mangle"
NFT_SET_CN4="set_cn4"
NFT_SET_PROXY4="set_proxy4"
NFT_SET_BYPASS_SRC4="set_bypass_src4"

# 文件路径
NFT_RULE_FILE="/etc/nftables.d/99-xray-transparent.nft"
XRAY_DIR="/etc/xray"
XRAY_CONF_DIR="/etc/xray/conf.d"
XRAY_MAIN_CFG="/etc/xray/config.json"
DNSMASQ_SPLIT="/etc/dnsmasq.d/split.conf"
DNSMASQ_CN_CONF="/etc/dnsmasq.d/cn-domains.conf"

DATA_DIR="/root/splittunnel"
DOMAINS_DIR="/root/splittunnel/domains"
IPSET_DIR="/root/splittunnel/ipset"
TPL_DIR="/root/splittunnel/templates"
README_FILE="/root/splittunnel/README.md"

CN4_TXT="/root/splittunnel/ipset/cn4.txt"
CN4_NFT="/root/splittunnel/ipset/cn4.nft"

PROXY_DOMAINS_TXT="/root/splittunnel/domains/proxy_domains.txt"
CN_DOMAINS_TXT="/root/splittunnel/domains/cn_domains.txt"

SELFCHECK="/root/selfcheck_splittunnel.sh"

LOG_FILE="/root/deploy_splittunnel.log"
LAST_BACKUP_PTR="/root/splittunnel.last_backup"

# CN IPv4 列表下载源（失败将终止部署并回滚，避免“伪 CN 集合”上线）
CN4_URL_1="https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"
CN4_URL_2="https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"

# geodata 下载源（作为备选；优先安装 xray-geodata 包）
GEODATA_URL_BASE="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
GEOSITE_NAME="geosite.dat"
GEOIP_NAME="geoip.dat"

#####################################
# 内部变量（不要改）
#####################################
FAIL=0
ROLLBACK_ONLY=0
BACKUP_DIR=""
TMPDIR="/tmp/deploy_splittunnel.$$"

#####################################
# 工具函数
#####################################
now_ts() { date "+%Y-%m-%d %H:%M:%S"; }

log() {
  msg="$1"
  printf "%s %s\n" "$(now_ts)" "$msg" | tee -a "$LOG_FILE"
}

ok()   { log "✅ $1"; }
warn() { log "⚠️  $1"; }
err()  { log "❌ $1"; FAIL=1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

cleanup() { rm -rf "$TMPDIR" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

mkdir_p() {
  d="$1"
  [ -d "$d" ] || mkdir -p "$d" >/dev/null 2>&1
}

backup_path() {
  p="$1"
  if [ -e "$p" ]; then
    dest="$BACKUP_DIR$p"
    dest_dir="$(dirname "$dest")"
    mkdir_p "$dest_dir"
    cp -a "$p" "$dest" >/dev/null 2>&1
    ok "已备份：$p -> $dest"
  else
    warn "备份跳过：$p 不存在"
  fi
}

restore_path() {
  p="$1"
  src="$BACKUP_DIR$p"
  if [ -e "$src" ]; then
    dest_dir="$(dirname "$p")"
    mkdir_p "$dest_dir"
    rm -rf "$p" >/dev/null 2>&1
    cp -a "$src" "$p" >/dev/null 2>&1
    ok "已恢复：$p"
  else
    if [ -e "$p" ]; then
      rm -rf "$p" >/dev/null 2>&1
      ok "已回滚删除（备份中不存在）：$p"
    fi
  fi
}

run() {
  cmd="$*"
  log "执行：$cmd"
  sh -c "$cmd" >>"$LOG_FILE" 2>&1
  rc=$?
  if [ $rc -ne 0 ]; then
    err "命令失败（退出码 $rc）：$cmd"
    return $rc
  fi
  return 0
}

usage() {
  cat <<EOF
用法：
  sh /root/deploy_splittunnel.sh
  sh /root/deploy_splittunnel.sh --rollback

说明：
  默认执行部署；--rollback 回滚到最近一次备份。
EOF
}

#####################################
# 参数解析
#####################################
while [ $# -gt 0 ]; do
  case "$1" in
    --rollback) ROLLBACK_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) warn "未知参数：$1（已忽略）" ;;
  esac
  shift
done

#####################################
# 回滚逻辑
#####################################
do_rollback() {
  if [ -f "$LAST_BACKUP_PTR" ]; then
    BACKUP_DIR="$(cat "$LAST_BACKUP_PTR" 2>/dev/null)"
  fi
  if [ -z "$BACKUP_DIR" ] || [ ! -d "$BACKUP_DIR" ]; then
    err "回滚失败：未找到最近备份目录（$LAST_BACKUP_PTR 不存在或内容无效）。建议：确认备份目录是否被删除。"
    return 1
  fi

  log "========== 开始回滚 =========="
  log "使用备份目录：$BACKUP_DIR"

  restore_path "$NFT_RULE_FILE"
  restore_path "$XRAY_DIR"
  restore_path "$DNSMASQ_SPLIT"
  restore_path "$DNSMASQ_CN_CONF"
  restore_path "$DATA_DIR"
  restore_path "$SELFCHECK"

  if have_cmd ip; then
    run "ip rule del fwmark 0x1 table 100 2>/dev/null || true"
    run "ip rule del fwmark 0x2 table 200 2>/dev/null || true"
    run "ip route flush table 100 || true"
    run "ip route flush table 200 || true"
  else
    warn "回滚提示：缺少 ip 命令，无法自动清理策略路由。"
  fi

  run "/etc/init.d/firewall restart || true"
  run "/etc/init.d/dnsmasq restart || true"
  run "/etc/init.d/xray restart || true"

  ok "回滚完成。建议：执行自检脚本确认系统恢复。"
  return 0
}

#####################################
# 仅回滚
#####################################
: > "$LOG_FILE"
mkdir_p "$TMPDIR"

if [ "$ROLLBACK_ONLY" -eq 1 ]; then
  do_rollback
  exit $?
fi

#####################################
# 部署前检查
#####################################
log "========== 开始部署旁路由分流系统 =========="
log "环境变量：LAN_SUBNET=$LAN_SUBNET 主路由=$MAIN_ROUTER_IP 旁路由=$SIDECAR_IP WG=$WG_IFACE"
log "强制约束：CN 必须在 nftables 层硬绕过（不进 Xray）；非 CN 经 TPROXY -> Xray -> wg0_out；非 CN DNS 也必须经 wg0"

if [ "$(id -u 2>/dev/null)" != "0" ]; then
  err "必须以 root 执行（失败原因：权限不足；建议：使用 root 账号）。"
  exit 1
fi

if ! have_cmd opkg; then
  err "未找到 opkg（失败原因：系统环境异常；建议：确认 OpenWrt 包管理可用）。"
  exit 1
fi

#####################################
# 探测 LAN_IFACE（基于 LAN_SUBNET 路由）
#####################################
detect_lan_iface() {
  if [ -n "$LAN_IFACE" ]; then
    return 0
  fi
  if ! have_cmd ip; then
    LAN_IFACE="br-lan"
    return 0
  fi
  # 例：192.168.88.0/24 dev br-lan scope link
  li="$(ip route show | grep -E "^$LAN_SUBNET[[:space:]]" | head -n 1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
  if [ -n "$li" ]; then
    LAN_IFACE="$li"
  else
    LAN_IFACE="br-lan"
  fi
}

detect_lan_iface
ok "LAN 接口：$LAN_IFACE（用于 nft 源接口限定，减少误引流）"

#####################################
# 创建备份
#####################################
BACKUP_DIR="/root/backup-$(date +%Y%m%d-%H%M%S)"
mkdir_p "$BACKUP_DIR"
echo "$BACKUP_DIR" > "$LAST_BACKUP_PTR" 2>/dev/null

log "备份目录：$BACKUP_DIR"
backup_path "$NFT_RULE_FILE"
backup_path "$XRAY_DIR"
backup_path "$DNSMASQ_SPLIT"
backup_path "$DNSMASQ_CN_CONF"
backup_path "$DATA_DIR"
backup_path "$SELFCHECK"

#####################################
# 依赖安装
#####################################
log "---------- 依赖检查/安装 ----------"
run "opkg update || true"

install_pkg() {
  pkg="$1"
  if opkg status "$pkg" >/dev/null 2>&1; then
    ok "已安装：$pkg"
    return 0
  fi
  log "尝试安装：$pkg"
  opkg install "$pkg" >>"$LOG_FILE" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then
    ok "安装成功：$pkg"
    return 0
  fi
  warn "安装失败：$pkg（可能源中无此包或依赖不满足；建议：检查 opkg 源/架构）"
  return 0
}

install_pkg "dnsmasq-full"
install_pkg "xray-core"
install_pkg "xray-geodata"
install_pkg "kmod-nft-tproxy"
install_pkg "kmod-nft-socket"
install_pkg "kmod-nf-tproxy"
install_pkg "kmod-nf-conntrack"
install_pkg "ip-full"
install_pkg "tcpdump"
install_pkg "bind-tools"
install_pkg "net-tools-netstat"

#####################################
# 检查 wg0
#####################################
log "---------- WireGuard 检查 ----------"
if ! have_cmd ip; then
  err "缺少 ip 命令（失败原因：无法检查 wg0/配置策略路由；建议：安装 ip-full）。"
  do_rollback
  exit 1
fi

if ip link show "$WG_IFACE" >/dev/null 2>&1; then
  st="$(ip link show "$WG_IFACE" 2>/dev/null | head -n 1)"
  echo "$st" | grep -q "UP" && ok "wg0 存在且 UP" || warn "wg0 存在但未显示 UP（建议：检查 peer/握手/ifstatus）"
else
  err "wg0 不存在（失败原因：接口名不匹配或未启用；建议：确认 WireGuard 接口名称固定为 wg0）。"
  do_rollback
  exit 1
fi

#####################################
# 写入目录结构与数据文件
#####################################
log "---------- 写入数据目录结构 ----------"
mkdir_p "$DATA_DIR"
mkdir_p "$DOMAINS_DIR"
mkdir_p "$IPSET_DIR"
mkdir_p "$TPL_DIR"

cat > "$PROXY_DOMAINS_TXT" <<'EOF'
# 可维护域名列表（后期扩展用）
# 每行一个域名（建议写根域）
# 示例：
# google.com
# github.com
EOF
ok "已写入：$PROXY_DOMAINS_TXT"

# 可维护 CN 域名列表（工程化：不再只靠 .cn）
# 说明：无法用 BusyBox sh 可靠解析 geosite.dat（二进制），因此用“可维护名单 + Xray geosite 兜底”的工程模型
cat > "$CN_DOMAINS_TXT" <<'EOF'
# 可维护 CN 域名列表（dnsmasq 前置分流用）
# 每行一个域名（根域/关键域），用于强制走国内 DNS（直连路径）
# 提示：此文件用于“前置分流与加速”，不追求覆盖 100% CN 站点；
#       未覆盖部分由 Xray geosite:cn/geoip:cn 做第二道保险兜底。
#
# 常用示例（可按需增删）：
baidu.com
qq.com
weixin.qq.com
weibo.com
taobao.com
tmall.com
jd.com
alicdn.com
bilibili.com
douyin.com
douyinpic.com
toutiao.com
csdn.net
zhihu.com
163.com
sina.com.cn
aliyun.com
tencent.com
mi.com
huawei.com
EOF
ok "已写入：$CN_DOMAINS_TXT"

# templates
cat > "$TPL_DIR/20-outbounds.with_proxy.json" <<'EOF'
{
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": {} },
    {
      "tag": "wg0_out",
      "protocol": "freedom",
      "settings": {},
      "streamSettings": { "sockopt": { "mark": 2 } }
    }
    // 未来新增：proxy outbound（模板）
  ]
}
EOF
ok "已写入模板：$TPL_DIR/20-outbounds.with_proxy.json"

cat > "$TPL_DIR/10-routing.with_balancer.json" <<'EOF'
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "balancers": [
      {
        "tag": "b_fallback",
        "selector": [ "proxy", "wg0_out" ],
        "strategy": { "type": "fallback" }
      }
    ],
    "rules": [
      { "type": "field", "ip": [ "geoip:cn", "geoip:private" ], "outboundTag": "direct" },
      { "type": "field", "domain": [ "geosite:cn" ], "outboundTag": "direct" },
      { "type": "field", "balancerTag": "b_fallback" }
    ]
  }
}
EOF
ok "已写入模板：$TPL_DIR/10-routing.with_balancer.json"

cat > "$README_FILE" <<EOF
# splittunnel 旁路由分流工程目录

## 当前阶段（无代理节点）
- CN：nftables 命中 set_cn4 直接 return（硬绕过，不进 Xray）
- 非 CN：TPROXY -> Xray -> wg0_out（sockopt.mark=2 强制走 table 200）
- DNS：客户端指向旁路由
  - dnsmasq 默认上游：127.0.0.1:${XRAY_DNS_PORT}（Xray DNS）
  - dnsmasq 前置 CN 加速：/root/splittunnel/domains/cn_domains.txt -> /etc/dnsmasq.d/cn-domains.conf
  - Xray DNS 兜底：geosite:cn 走国内 DNS，非 CN DNS 明确 detour wg0_out

## 文件
- $CN_DOMAINS_TXT：可维护 CN 域名列表（用于 dnsmasq 前置加速/分流）
- $DNSMASQ_CN_CONF：由部署脚本编译生成（不要手改，改 txt 再重跑部署）
- templates/：后期扩展 proxy + fallback 模板

## 运维
- 部署日志：$LOG_FILE
- 自检脚本：$SELFCHECK
EOF
ok "已写入：$README_FILE"

#####################################
# 编译生成 dnsmasq CN 域名规则：/etc/dnsmasq.d/cn-domains.conf
#####################################
log "---------- 生成 dnsmasq CN 域名规则（工程化） ----------"
rm -f "$DNSMASQ_CN_CONF" >/dev/null 2>&1
{
  echo "# 自动生成：$(now_ts)"
  echo "# 来源：$CN_DOMAINS_TXT"
  echo "# 作用：将这些域名强制使用国内 DNS（直连路径），作为前置加速/分流"
  echo "server=/cn/223.5.5.5"
  echo "server=/cn/119.29.29.29"
  echo ""
  while IFS= read -r d; do
    # 去空格/注释
    d="$(echo "$d" | sed 's/[[:space:]]//g')"
    [ -z "$d" ] && continue
    echo "$d" | grep -q "^#" && continue
    # 基本域名格式校验（宽松）
    echo "$d" | grep -qE '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' || continue
    echo "server=/$d/223.5.5.5"
    echo "server=/$d/119.29.29.29"
  done < "$CN_DOMAINS_TXT"
} > "$DNSMASQ_CN_CONF" 2>/dev/null
ok "已生成：$DNSMASQ_CN_CONF"

#####################################
# 获取/生成 CN IPv4 列表与 cn4.nft
#####################################
log "---------- 生成 CN IPv4 nft set ----------"
download_to() {
  url="$1"; out="$2"
  if have_cmd uclient-fetch; then uclient-fetch -O "$out" "$url" >>"$LOG_FILE" 2>&1 && return 0; fi
  if have_cmd wget; then wget -O "$out" "$url" >>"$LOG_FILE" 2>&1 && return 0; fi
  if have_cmd curl; then curl -L -o "$out" "$url" >>"$LOG_FILE" 2>&1 && return 0; fi
  return 1
}

need_dl=0
if [ ! -f "$CN4_TXT" ]; then
  need_dl=1
else
  sz="$(wc -l < "$CN4_TXT" 2>/dev/null | tr -d ' ')"
  [ -z "$sz" ] && sz=0
  [ "$sz" -lt 1000 ] && need_dl=1
fi

if [ "$need_dl" -eq 1 ]; then
  tmp_cn="$TMPDIR/cn4.txt"
  rm -f "$tmp_cn" >/dev/null 2>&1
  log "尝试下载 CN IPv4 列表：$CN4_URL_1"
  if download_to "$CN4_URL_1" "$tmp_cn"; then
    ok "下载成功：CN IPv4 列表（源 1）"
  else
    warn "源 1 下载失败，尝试源 2：$CN4_URL_2"
    rm -f "$tmp_cn" >/dev/null 2>&1
    if download_to "$CN4_URL_2" "$tmp_cn"; then
      ok "下载成功：CN IPv4 列表（源 2）"
    else
      err "CN IPv4 列表下载失败（失败原因：无法获取 cn4；建议：检查 DNS/网络，或手工放置 $CN4_TXT 后重跑）。"
      do_rollback; exit 1
    fi
  fi
  grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$tmp_cn" | sed 's/[[:space:]].*$//' > "$CN4_TXT" 2>/dev/null
  ok "已更新：$CN4_TXT"
fi

rm -f "$CN4_NFT" >/dev/null 2>&1
touch "$CN4_NFT" >/dev/null 2>&1
echo "# 自动生成：$(now_ts)" >> "$CN4_NFT"
echo "flush set $NFT_TABLE_FAMILY $NFT_TABLE_NAME $NFT_SET_CN4" >> "$CN4_NFT"

chunk=""
count=0
added=0
while IFS= read -r cidr; do
  [ -z "$cidr" ] && continue
  echo "$cidr" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' || continue
  if [ -z "$chunk" ]; then chunk="$cidr"; else chunk="$chunk, $cidr"; fi
  count=$((count + 1)); added=$((added + 1))
  if [ $count -ge 500 ]; then
    echo "add element $NFT_TABLE_FAMILY $NFT_TABLE_NAME $NFT_SET_CN4 { $chunk }" >> "$CN4_NFT"
    chunk=""; count=0
  fi
done < "$CN4_TXT"
[ -n "$chunk" ] && echo "add element $NFT_TABLE_FAMILY $NFT_TABLE_NAME $NFT_SET_CN4 { $chunk }" >> "$CN4_NFT"

if [ "$added" -le 0 ]; then
  err "CN IPv4 列表为空（失败原因：cn4.txt 无有效 CIDR；建议：检查下载源或手工提供）。"
  do_rollback; exit 1
fi
ok "已生成：$CN4_NFT（包含 $added 条 CIDR）"

#####################################
# 写 nftables 规则：增加 LAN_IFACE 源接口限定
#####################################
log "---------- 写入 nftables 规则（含源接口限定） ----------"
cat > "$NFT_RULE_FILE" <<EOF
# $NFT_RULE_FILE
# 自定义透明引流 table：$NFT_TABLE_FAMILY $NFT_TABLE_NAME
# 关键要求：
# - 禁止 flush ruleset
# - 禁止修改/重定义 inet fw4
# - CN 硬绕过：ip daddr @$NFT_SET_CN4 return 必须位于任何 tproxy 之前
# - 源接口限定：只处理来自 LAN 接口 $LAN_IFACE 的入站流量，减少误引流

table $NFT_TABLE_FAMILY $NFT_TABLE_NAME {

  set $NFT_SET_CN4 {
    type ipv4_addr
    flags interval
    auto-merge
  }

  set $NFT_SET_PROXY4 {
    type ipv4_addr
    flags interval
    auto-merge
  }

  set $NFT_SET_BYPASS_SRC4 {
    type ipv4_addr
    flags interval
    elements = { $MAIN_ROUTER_IP, $SIDECAR_IP }
  }

  chain $NFT_CHAIN_PREROUTING {
    type filter hook prerouting priority mangle; policy accept;

    # 0) 仅处理来自 LAN 的入站流量（源接口限定）
    iifname != "$LAN_IFACE" return

    # 1) 源 IP 绕过（可维护）
    ip saddr @$NFT_SET_BYPASS_SRC4 return

    # 2) 目的为本地/组播/广播/私网：绕过
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
               172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return

    # 3) CN 目的 IP：硬绕过（必须在任何 tproxy 之前）
    ip daddr @$NFT_SET_CN4 return

    # 4) 非 CN 流量 TPROXY 引流（TCP/UDP）
    meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT mark set 0x1
  }

  include "$CN4_NFT"
}
EOF
ok "已写入：$NFT_RULE_FILE"

#####################################
# 写 Xray conf.d + include 降级
#####################################
log "---------- 写入 Xray 配置（conf.d + include -> 自动降级） ----------"
mkdir_p "$XRAY_CONF_DIR"

cat > "$XRAY_CONF_DIR/00-inbounds.json" <<EOF
{
  "inbounds": [
    {
      "tag": "tproxy-in",
      "listen": "0.0.0.0",
      "port": $TPROXY_PORT,
      "protocol": "dokodemo-door",
      "settings": { "network": "tcp,udp", "followRedirect": true },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": true }
    },
    {
      "tag": "dns-in",
      "listen": "127.0.0.1",
      "port": $XRAY_DNS_PORT,
      "protocol": "dokodemo-door",
      "settings": { "network": "udp,tcp", "address": "1.1.1.1", "port": 53 }
    }
  ]
}
EOF

cat > "$XRAY_CONF_DIR/20-outbounds.json" <<EOF
{
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": {} },
    {
      "tag": "wg0_out",
      "protocol": "freedom",
      "settings": {},
      "streamSettings": { "sockopt": { "mark": 2 } }
    },
    { "tag": "dns-out", "protocol": "dns", "settings": {} }
  ]
}
EOF

cat > "$XRAY_CONF_DIR/10-routing.json" <<'EOF'
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": [ "dns-in" ], "outboundTag": "dns-out" },
      { "type": "field", "ip": [ "geoip:private", "geoip:cn" ], "outboundTag": "direct" },
      { "type": "field", "domain": [ "geosite:cn" ], "outboundTag": "direct" },
      { "type": "field", "outboundTag": "wg0_out" }
    ]
  }
}
EOF

cat > "$XRAY_CONF_DIR/30-dns.json" <<EOF
{
  "dns": {
    "queryStrategy": "UseIPv4",
    "servers": [
      { "tag": "dns_cn", "address": "223.5.5.5", "port": 53 },
      { "tag": "dns_noncn", "address": "8.8.8.8", "port": 53, "detour": "wg0_out" },
      { "tag": "dns_noncn_2", "address": "1.1.1.1", "port": 53, "detour": "wg0_out" }
    ],
    "rules": [
      { "type": "field", "domain": [ "geosite:cn" ], "server": "dns_cn" }
    ]
  }
}
EOF
ok "已写入拆分配置：$XRAY_CONF_DIR"

# geodata 检查/下载
log "---------- geosite/geoip 数据检查 ----------"
GEODIR1="/usr/share/xray"
GEODIR2="/usr/share/v2ray"
GEO_OK=0
if [ -f "$GEODIR1/$GEOSITE_NAME" ] && [ -f "$GEODIR1/$GEOIP_NAME" ]; then GEO_OK=1; ok "发现 geodata：$GEODIR1"; fi
if [ "$GEO_OK" -ne 1 ] && [ -f "$GEODIR2/$GEOSITE_NAME" ] && [ -f "$GEODIR2/$GEOIP_NAME" ]; then GEO_OK=1; ok "发现 geodata：$GEODIR2"; fi
if [ "$GEO_OK" -ne 1 ]; then
  warn "未在常见路径发现 geodata，尝试下载到 $GEODIR1（失败不会终止，但会影响 geosite/geoip 兜底）"
  mkdir_p "$GEODIR1"
  download_to "$GEODATA_URL_BASE/$GEOSITE_NAME" "$GEODIR1/$GEOSITE_NAME" || true
  download_to "$GEODATA_URL_BASE/$GEOIP_NAME" "$GEODIR1/$GEOIP_NAME" || true
fi

# include 尝试 + 自动降级
cat > "$XRAY_MAIN_CFG" <<EOF
{
  "log": { "loglevel": "warning" },
  "include": [ "$XRAY_CONF_DIR/*.json" ]
}
EOF
ok "已写入 include 版本：$XRAY_MAIN_CFG"

XRAY_TEST_OK=0
if have_cmd xray && xray run -test -config "$XRAY_MAIN_CFG" >>"$LOG_FILE" 2>&1; then
  XRAY_TEST_OK=1
  ok "Xray include 配置测试通过"
else
  warn "Xray include 配置测试失败，自动生成等价单文件降级"
fi

if [ "$XRAY_TEST_OK" -ne 1 ]; then
  cat > "$XRAY_MAIN_CFG" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "tproxy-in",
      "listen": "0.0.0.0",
      "port": $TPROXY_PORT,
      "protocol": "dokodemo-door",
      "settings": { "network": "tcp,udp", "followRedirect": true },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": true }
    },
    {
      "tag": "dns-in",
      "listen": "127.0.0.1",
      "port": $XRAY_DNS_PORT,
      "protocol": "dokodemo-door",
      "settings": { "network": "udp,tcp", "address": "1.1.1.1", "port": 53 }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": {} },
    { "tag": "wg0_out", "protocol": "freedom", "settings": {}, "streamSettings": { "sockopt": { "mark": 2 } } },
    { "tag": "dns-out", "protocol": "dns", "settings": {} }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": [ "dns-in" ], "outboundTag": "dns-out" },
      { "type": "field", "ip": [ "geoip:private", "geoip:cn" ], "outboundTag": "direct" },
      { "type": "field", "domain": [ "geosite:cn" ], "outboundTag": "direct" },
      { "type": "field", "outboundTag": "wg0_out" }
    ]
  },
  "dns": {
    "queryStrategy": "UseIPv4",
    "servers": [
      { "tag": "dns_cn", "address": "223.5.5.5", "port": 53 },
      { "tag": "dns_noncn", "address": "8.8.8.8", "port": 53, "detour": "wg0_out" },
      { "tag": "dns_noncn_2", "address": "1.1.1.1", "port": 53, "detour": "wg0_out" }
    ],
    "rules": [ { "type": "field", "domain": [ "geosite:cn" ], "server": "dns_cn" } ]
  }
}
EOF
  ok "已生成单文件等价配置：$XRAY_MAIN_CFG"
  if have_cmd xray && xray run -test -config "$XRAY_MAIN_CFG" >>"$LOG_FILE" 2>&1; then
    ok "单文件配置测试通过"
  else
    err "单文件配置测试失败（失败原因：Xray 配置语法/版本不兼容；建议：查看 $LOG_FILE 中 xray -test 输出）"
    do_rollback; exit 1
  fi
fi

#####################################
# 写 dnsmasq split.conf（不改 /etc/config/dhcp）
#####################################
log "---------- 写入 dnsmasq 分流配置 ----------"
mkdir_p "/etc/dnsmasq.d"

cat > "$DNSMASQ_SPLIT" <<EOF
# $DNSMASQ_SPLIT
# 关键点：
# - dnsmasq-full
# - 不修改 /etc/config/dhcp
# - no-resolv 防泄漏
# - 默认上游：127.0.0.1#$XRAY_DNS_PORT（Xray DNS）
# - CN 域名前置：由 $DNSMASQ_CN_CONF 提供（可维护源 $CN_DOMAINS_TXT）

no-resolv
strict-order
cache-size=10000
domain-needed
bogus-priv
stop-dns-rebind

# 默认全部交给本机 Xray DNS（由 Xray DNS 规则决定 CN 走国内、非 CN 走 wg0 detour）
server=127.0.0.1#$XRAY_DNS_PORT
EOF
ok "已写入：$DNSMASQ_SPLIT"

#####################################
# 策略路由（幂等）
#####################################
log "---------- 设置策略路由（mark -> table） ----------"
run "ip rule del fwmark 0x1 table 100 2>/dev/null || true"
run "ip rule del fwmark 0x2 table 200 2>/dev/null || true"
run "ip route flush table 100 || true"
run "ip route flush table 200 || true"

run "ip rule add fwmark 0x1 table 100 priority 100"
run "ip route add local default dev lo table 100"

run "ip rule add fwmark 0x2 table 200 priority 200"
run "ip route add default dev $WG_IFACE metric 10 table 200"
run "ip route add unreachable default metric 1000 table 200"
ok "策略路由已配置：0x1->100(lo), 0x2->200(wg0 + unreachable)"

#####################################
# 写入运维级自检脚本 /root/selfcheck_splittunnel.sh（并在部署末尾调用）
#####################################
log "---------- 写入运维级自检脚本 ----------"
cat > "$SELFCHECK" <<'EOF'
#!/bin/sh
# /root/selfcheck_splittunnel.sh
# 运维级自检：OpenWrt 23.05 旁路由分流（nftables + Xray + dnsmasq-full + WireGuard）
# BusyBox sh 兼容

LAN_SUBNET="192.168.88.0/24"
SIDECAR_IP="192.168.88.200"
WG_IFACE="wg0"
NFT_TABLE_FAMILY="inet"
NFT_TABLE_NAME="xray_tproxy"
NFT_CHAIN_PREROUTING="prerouting_mangle"
NFT_SET_CN4="set_cn4"
TPROXY_PORT="12345"
XRAY_DNS_PORT="5353"
XRAY_DIR="/etc/xray"
DNSMASQ_DIR="/etc/dnsmasq.d"
LOG_FILE="/root/selfcheck_splittunnel.log"
FAIL=0
WARN=0
CAPTURE=0

now_ts(){ date "+%Y-%m-%d %H:%M:%S"; }
log(){ printf "%s %s\n" "$(now_ts)" "$1" | tee -a "$LOG_FILE"; }
ok(){ log "✅ $1"; }
warn(){ WARN=$((WARN+1)); log "⚠️  $1"; }
fail(){ FAIL=$((FAIL+1)); log "❌ $1"; }
have_cmd(){ command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --capture) CAPTURE=1 ;;
  esac
  shift
done

: > "$LOG_FILE"
log "========== 分流系统运维级自检开始 =========="

# wg0
if have_cmd ip && ip link show "$WG_IFACE" >/dev/null 2>&1; then
  l="$(ip link show "$WG_IFACE" | head -n1)"
  echo "$l" | grep -q "UP" && ok "wg0 存在且 UP" || warn "wg0 存在但未 UP（检查 WireGuard）"
else
  fail "wg0 不存在或无法读取（检查接口名/网络服务）"
fi

# nft 规则顺序验收
if ! have_cmd nft; then
  fail "缺少 nft 命令（无法验收 nftables）"
else
  nft list tables 2>/dev/null | grep -q "^table $NFT_TABLE_FAMILY $NFT_TABLE_NAME" \
    && ok "nft 表存在：$NFT_TABLE_FAMILY $NFT_TABLE_NAME" \
    || fail "nft 表不存在：$NFT_TABLE_FAMILY $NFT_TABLE_NAME（检查 fw4 include）"

  c="$(nft list chain "$NFT_TABLE_FAMILY" "$NFT_TABLE_NAME" "$NFT_CHAIN_PREROUTING" 2>/dev/null)"
  if [ -z "$c" ]; then
    fail "无法读取链：$NFT_CHAIN_PREROUTING"
  else
    cn="$(echo "$c" | awk 'BEGIN{n=0;ans=0}{n++; if(ans==0 && $0~ /ip daddr @'"$NFT_SET_CN4"' return/){ans=n}} END{print ans}')"
    tp="$(echo "$c" | awk 'BEGIN{n=0;ans=0}{n++; if(ans==0 && $0~ / tproxy /){ans=n}} END{print ans}')"
    [ "$cn" -gt 0 ] && ok "发现 CN return（行号 $cn）" || fail "缺失 CN return（违反硬绕过）"
    [ "$tp" -gt 0 ] && ok "发现 tproxy（行号 $tp）" || warn "未发现 tproxy（可能未启用引流）"
    if [ "$cn" -gt 0 ] && [ "$tp" -gt 0 ]; then
      [ "$cn" -lt "$tp" ] && ok "验收通过：CN return 在 tproxy 前" || fail "验收失败：CN return 在 tproxy 后（CN 会进 Xray）"
    fi
  fi

  s="$(nft list set "$NFT_TABLE_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET_CN4" 2>/dev/null)"
  cnt="$(echo "$s" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' | wc -l | tr -d " ")"
  [ -z "$cnt" ] && cnt=0
  [ "$cnt" -gt 0 ] && ok "CN 集合非空（粗略统计 $cnt）" || fail "CN 集合为空（CN 硬绕过不可用）"
fi

# 策略路由
if have_cmd ip; then
  ip rule | grep -q "fwmark 0x1.*lookup 100" && ok "存在：fwmark 0x1 -> table 100" || fail "缺失：fwmark 0x1 -> table 100"
  ip route show table 100 | grep -q "^local default dev lo" && ok "table 100 正确：local default dev lo" || fail "table 100 不正确"
  ip rule | grep -q "fwmark 0x2.*lookup 200" && ok "存在：fwmark 0x2 -> table 200" || fail "缺失：fwmark 0x2 -> table 200"
  ip route show table 200 | grep -q "^default dev" && ok "table 200 存在默认路由" || fail "table 200 缺少默认路由"
  ip route show table 200 | grep -q "^unreachable default" && ok "table 200 存在 unreachable 兜底" || fail "table 200 缺少 unreachable 兜底（可能回落直连）"
else
  fail "缺少 ip 命令（无法验收策略路由）"
fi

# 端口监听（ss/netstat）
listen_any(){
  p="$1"
  if have_cmd ss; then ss -lntup 2>/dev/null | grep -q ":$p" && return 0; fi
  if have_cmd netstat; then netstat -lntup 2>/dev/null | grep -q ":$p" && return 0; fi
  return 1
}
listen_udp(){
  p="$1"
  if have_cmd ss; then ss -lunp 2>/dev/null | grep -q ":$p" && return 0; fi
  if have_cmd netstat; then netstat -lunp 2>/dev/null | grep -q ":$p" && return 0; fi
  return 1
}

listen_any "$TPROXY_PORT" && ok "Xray 监听 :$TPROXY_PORT" || fail "Xray 未监听 :$TPROXY_PORT"
listen_udp "$XRAY_DNS_PORT" && ok "Xray DNS 监听 :$XRAY_DNS_PORT" || warn "未检测到 Xray DNS 监听 :$XRAY_DNS_PORT"

# dnsmasq confdir 加载与默认上游
if [ -d "$DNSMASQ_DIR" ]; then
  grep -Rqs "^no-resolv" "$DNSMASQ_DIR"/*.conf 2>/dev/null && ok "dnsmasq 启用 no-resolv" || fail "dnsmasq 未启用 no-resolv（有泄漏风险）"
  grep -Rqs "server=127\.0\.0\.1#${XRAY_DNS_PORT}" "$DNSMASQ_DIR"/*.conf 2>/dev/null && ok "dnsmasq 默认上游指向 Xray DNS" || fail "dnsmasq 默认上游未指向 Xray DNS"
else
  fail "dnsmasq.d 不存在（confdir 可能未启用）"
fi

# Xray detour wg0_out（防 DNS 泄漏的关键点）
if [ -d "$XRAY_DIR" ] && grep -Rqs "\"detour\"[[:space:]]*:[[:space:]]*\"wg0_out\"" "$XRAY_DIR" 2>/dev/null; then
  ok "Xray 配置包含 detour: wg0_out（DNS/流量出口锁定 wg0）"
else
  fail "未发现 detour: wg0_out（非 CN DNS 可能泄漏到主路由）"
fi

if [ "$FAIL" -eq 0 ]; then
  ok "自检通过：FAIL=0 WARN=$WARN（允许上线）"
  exit 0
fi
fail "自检失败：FAIL=$FAIL WARN=$WARN（禁止上线，按日志逐项修复）"
exit 1
EOF
chmod +x "$SELFCHECK" >/dev/null 2>&1
ok "已写入：$SELFCHECK"

#####################################
# 重载/重启服务
#####################################
log "---------- 重载/重启服务 ----------"
run "/etc/init.d/network reload || true"
run "/etc/init.d/firewall restart || true"
run "/etc/init.d/dnsmasq restart || true"
run "/etc/init.d/xray restart || true"

#####################################
# 部署后：自动运行运维级自检（失败自动回滚）
#####################################
log "========== 部署后自动自检（运维级）=========="
sh "$SELFCHECK" >>"$LOG_FILE" 2>&1
rc=$?
if [ $rc -eq 0 ]; then
  ok "部署后自检通过：系统已具备上线条件"
  log "提示：如需强证据链抓包，请执行：sh $SELFCHECK --capture（并从客户端访问 CN/非CN 站点）"
  log "========== 部署完成 =========="
  exit 0
fi

err "部署后自检失败（失败原因：关键验收不通过；建议：查看 $LOG_FILE 与 /root/selfcheck_splittunnel.log）"
log "触发自动回滚：避免异常配置上线"
do_rollback
exit 1
