#!/bin/sh
# /root/selfcheck_splittunnel.sh
# 运维级自检：OpenWrt 23.05 旁路由分流（nftables + Xray + dnsmasq-full + WireGuard）
# BusyBox sh 兼容：不使用数组 / 不使用 [[ ]] / 不依赖 bash 特性

#####################################
# 变量集中区（按需修改）
#####################################
LAN_SUBNET="192.168.88.0/24"
MAIN_ROUTER_IP="192.168.88.1"
SIDECAR_IP="192.168.88.200"
WG_IFACE="wg0"

NFT_TABLE_FAMILY="inet"
NFT_TABLE_NAME="xray_tproxy"
NFT_CHAIN_PREROUTING="prerouting_mangle"
NFT_SET_CN4="set_cn4"

TPROXY_PORT="12345"
XRAY_DNS_PORT="5353"

XRAY_DIR="/etc/xray"
XRAY_CONF_DIR="/etc/xray/conf.d"
DNSMASQ_DIR="/etc/dnsmasq.d"

# DNS 功能测试用域名（按需改）
TEST_CN_DOMAIN="www.baidu.com"
TEST_NONCN_DOMAIN="www.google.com"

LOG_FILE="/root/selfcheck_splittunnel.log"

#####################################
# 内部变量（不要改）
#####################################
FAIL=0
WARN=0
CAPTURE=0
JSON=0
TMPDIR="/tmp/selfcheck_splittunnel.$$"

CN_CAP_FILE="$TMPDIR/cap_cn.txt"
NONCN_CAP_FILE="$TMPDIR/cap_noncn.txt"
DNSWG_CAP_FILE="$TMPDIR/cap_dnswg.txt"

#####################################
# 工具函数
#####################################
now_ts() { date "+%Y-%m-%d %H:%M:%S"; }

log() {
  msg="$1"
  printf "%s %s\n" "$(now_ts)" "$msg" | tee -a "$LOG_FILE" >/dev/null
}

ok()   { log "✅ $1"; }
warn() { WARN=$((WARN + 1)); log "⚠️  $1"; }
fail() { FAIL=$((FAIL + 1)); log "❌ $1"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

cleanup() { rm -rf "$TMPDIR" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

mk_tmpdir() {
  mkdir -p "$TMPDIR" >/dev/null 2>&1
  : > "$CN_CAP_FILE" 2>/dev/null
  : > "$NONCN_CAP_FILE" 2>/dev/null
  : > "$DNSWG_CAP_FILE" 2>/dev/null
}

usage() {
  cat <<EOF
用法：
  sh /root/selfcheck_splittunnel.sh [--capture] [--json]

参数：
  --capture  启用抓包辅助验证（需要你从“客户端”访问 CN/非CN 网站）
  --json     输出一段 JSON 自检摘要（便于自动化采集）
EOF
}

#####################################
# 参数解析
#####################################
while [ $# -gt 0 ]; do
  case "$1" in
    --capture) CAPTURE=1 ;;
    --json) JSON=1 ;;
    -h|--help) usage; exit 0 ;;
    *) warn "未知参数：$1（已忽略）" ;;
  esac
  shift
done

#####################################
# 兜底：端口监听检测（ss / netstat）
#####################################
is_listening_port() {
  # $1 proto: tcp|udp|any  $2 port
  proto="$1"; port="$2"
  if have_cmd ss; then
    case "$proto" in
      tcp) ss -lntp 2>/dev/null | grep -q ":$port" ;;
      udp) ss -lunp 2>/dev/null | grep -q ":$port" ;;
      any) ss -lntup 2>/dev/null | grep -q ":$port" ;;
      *) return 1 ;;
    esac
    return $?
  fi
  if have_cmd netstat; then
    case "$proto" in
      tcp) netstat -lntp 2>/dev/null | grep -q ":$port" ;;
      udp) netstat -lunp 2>/dev/null | grep -q ":$port" ;;
      any) netstat -lntup 2>/dev/null | grep -q ":$port" ;;
      *) return 1 ;;
    esac
    return $?
  fi
  return 2
}

#####################################
# 兜底：进程检测（pgrep / ps）
#####################################
is_running_proc() {
  p="$1"
  if have_cmd pgrep; then
    pgrep "$p" >/dev/null 2>&1 && return 0
    return 1
  fi
  ps 2>/dev/null | grep -v "grep" | grep -q "$p"
  return $?
}

#####################################
# nft set 元素统计（解析 elements 块）
#####################################
nft_set_count_elements() {
  set_out="$1"
  echo "$set_out" | awk '
    BEGIN{in=0; buf="";}
    /elements[[:space:]]*=[[:space:]]*{/ {in=1; sub(/^.*elements[[:space:]]*=[[:space:]]*{/, "", $0); buf=buf $0 "\n"; next}
    in==1 { buf=buf $0 "\n" }
    /}/ && in==1 { in=0 }
    END{
      gsub(/[{}]/, "", buf)
      gsub(/[\r\n\t]/, " ", buf)
      while (buf ~ /  /) gsub(/  /, " ", buf)
      tmp=buf; gsub(/[[:space:]]/, "", tmp)
      if (tmp=="") { print 0; exit }
      n=split(buf, a, ",")
      c=0
      for(i=1;i<=n;i++){
        t=a[i]
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
        if(t!="") c++
      }
      print c
    }'
}

#####################################
# 运维级：打印关键配置片段（定位责任层）
#####################################
show_file_snippet() {
  # $1 file  $2 pattern  $3 max_lines
  f="$1"; pat="$2"; max="$3"
  [ -z "$max" ] && max="40"
  if [ -f "$f" ]; then
    hit="$(grep -nE "$pat" "$f" 2>/dev/null | head -n "$max")"
    if [ -n "$hit" ]; then
      log "—— 命中配置片段：$f"
      echo "$hit" | while IFS= read -r line; do
        log "   $line"
      done
    fi
  fi
}

show_xray_dns_related() {
  # 尽可能定位 Xray DNS / detour / servers
  log "【定位】Xray DNS/出口相关片段（便于快速排障）"
  if [ -f "$XRAY_DIR/config.json" ]; then
    show_file_snippet "$XRAY_DIR/config.json" '("dns"|dns|servers|detour|wg0_out|5353)' 60
  fi
  if [ -d "$XRAY_CONF_DIR" ]; then
    for f in "$XRAY_CONF_DIR"/*.json; do
      [ -f "$f" ] || continue
      show_file_snippet "$f" '("dns"|dns|servers|detour|wg0_out|5353)' 60
    done
  fi
}

show_dnsmasq_related() {
  log "【定位】dnsmasq 分流相关片段（便于快速排障）"
  for f in "$DNSMASQ_DIR"/*.conf; do
    [ -f "$f" ] || continue
    show_file_snippet "$f" '^(no-resolv|strict-order|server=|conf-dir=|nftset=|ipset=|cache-size=)' 80
  done
}

#####################################
# 运维级：DNS 功能测试（nslookup）
#####################################
dns_test_nslookup() {
  # $1 domain  $2 label(CN/NONCN)
  dom="$1"; label="$2"

  if ! have_cmd nslookup; then
    warn "未安装 nslookup（busybox nslookup 或 bind-tools）。建议：opkg install bind-tools（用于更可靠 DNS 诊断）"
    return 2
  fi

  # 通过旁路由自身的 53 端口测（证明 dnsmasq 作为控制平面）
  out="$(nslookup "$dom" "$SIDECAR_IP" 2>/dev/null)"
  if echo "$out" | grep -qi "server can't find\|NXDOMAIN\|SERVFAIL\|timed out\|no servers could be reached"; then
    fail "DNS 功能测试（$label）：通过 $SIDECAR_IP 查询 $dom 失败（失败原因：dnsmasq 未工作/未监听/上游不通；建议：logread -e dnsmasq；检查 split.conf 与 53 端口）"
    log "【定位】nslookup 输出："
    echo "$out" | head -n 30 | while IFS= read -r line; do log "   $line"; done
    return 1
  fi

  # 粗略判断是否拿到了 Address
  if echo "$out" | grep -qE "Address:[[:space:]]*([0-9]{1,3}\.){3}[0-9]{1,3}"; then
    ok "DNS 功能测试（$label）：通过 $SIDECAR_IP 成功解析 $dom"
    return 0
  fi

  # 也可能只返回了 server 地址等信息
  warn "DNS 功能测试（$label）：nslookup 未明确返回 IPv4 Address（可能仅返回 AAAA 或输出格式不同）。建议：打印输出核对。"
  log "【定位】nslookup 输出："
  echo "$out" | head -n 30 | while IFS= read -r line; do log "   $line"; done
  return 0
}

#####################################
# 自检开始
#####################################
: > "$LOG_FILE"
mk_tmpdir
log "========== 旁路由分流系统 自检开始（运维级）=========="
log "环境：LAN_SUBNET=$LAN_SUBNET 主路由=$MAIN_ROUTER_IP 旁路由=$SIDECAR_IP WG=$WG_IFACE"
log "目标：CN 硬绕过（不进 Xray），非 CN 经 TPROXY 进入 Xray 后走 wg0_out；DNS 路径与转发路径一致"
log "--------------------------------------------"

#####################################
# 0/8 基础环境
#####################################
log "【0/8】基础环境检查"

if have_cmd ip; then
  if ip link show "$WG_IFACE" >/dev/null 2>&1; then
    state_line="$(ip link show "$WG_IFACE" 2>/dev/null | head -n 1)"
    echo "$state_line" | grep -q "UP" && ok "WireGuard 接口 $WG_IFACE 存在且为 UP" || warn "WireGuard 接口 $WG_IFACE 存在但未显示 UP（建议：ifstatus $WG_IFACE / 检查 peer/握手）"
  else
    fail "WireGuard 接口 $WG_IFACE 不存在（建议：确认 wg0 配置与网络服务状态）"
  fi
else
  fail "缺少 ip 命令（建议：检查 busybox/ip-full）"
fi

if have_cmd wg; then
  if wg show "$WG_IFACE" >/dev/null 2>&1; then
    hs="$(wg show "$WG_IFACE" 2>/dev/null | grep -i "latest handshake" | head -n 1)"
    [ -n "$hs" ] && ok "wg 状态可读取：$hs" || warn "wg 状态可读取，但未发现 handshake 字段（可能无 peer 或未握手）"
  else
    warn "wg 命令存在但无法读取 $WG_IFACE（建议：检查 wireguard-tools 与接口是否一致）"
  fi
else
  warn "未安装 wg 工具（建议：opkg install wireguard-tools）"
fi

if is_running_proc xray; then
  ok "Xray 进程存在"
else
  fail "Xray 进程不存在（建议：logread -e xray；/etc/init.d/xray status）"
fi

if have_cmd dnsmasq; then
  feat="$(dnsmasq -v 2>/dev/null | tr ' ' '\n' | grep -E 'ipset|nftset' | tr '\n' ' ')"
  ver="$(dnsmasq -v 2>/dev/null | head -n 1)"
  if echo "$feat" | grep -q "ipset\|nftset"; then
    ok "dnsmasq 支持 ipset/nftset（疑似 dnsmasq-full）：$ver"
  else
    fail "dnsmasq 不含 ipset/nftset 特征（建议：安装 dnsmasq-full，并移除 dnsmasq）"
  fi
else
  fail "未找到 dnsmasq（建议：安装 dnsmasq-full 并确认服务启动）"
fi

# 端口：dnsmasq 53
r53="$(is_listening_port udp 53; echo $?)"
if [ "$r53" -eq 0 ]; then
  ok "检测到 53/udp 端口监听（dnsmasq 可能已就绪）"
elif [ "$r53" -eq 2 ]; then
  warn "缺少 ss/netstat，无法确认 53 端口监听（建议：安装 ip-full 或 net-tools-netstat）"
else
  fail "未检测到 53/udp 监听（失败原因：dnsmasq 未启动或未绑定；建议：/etc/init.d/dnsmasq restart；logread -e dnsmasq）"
  show_dnsmasq_related
fi

log "--------------------------------------------"

#####################################
# 1/8 TPROXY 依赖检查
#####################################
log "【1/8】TPROXY 依赖检查（模块/能力）"
if have_cmd lsmod; then
  mods="$(lsmod 2>/dev/null)"
  echo "$mods" | grep -q -E 'nft_tproxy|nf_tproxy|xt_TPROXY' \
    && ok "检测到 TPROXY 相关模块已加载（nft_tproxy/nf_tproxy/xt_TPROXY 之一）" \
    || warn "未检测到常见 TPROXY 模块（可能仍可用但风险高；建议：确认 kmod-nft-tproxy / kmod-nf-tproxy 等已安装并重载）"
else
  warn "缺少 lsmod（无法确认内核模块；建议：用行为抓包验证引流）"
fi

log "--------------------------------------------"

#####################################
# 2/8 nftables 核心验收
#####################################
log "【2/8】nftables 规则检查（关键验收）"

if ! have_cmd nft; then
  fail "未找到 nft 命令（建议：确认 firewall4/nftables 组件）"
else
  tables="$(nft list tables 2>/dev/null)"

  echo "$tables" | grep -q "^table $NFT_TABLE_FAMILY $NFT_TABLE_NAME" \
    && ok "自定义表存在：$NFT_TABLE_FAMILY $NFT_TABLE_NAME" \
    || fail "自定义表不存在：$NFT_TABLE_FAMILY $NFT_TABLE_NAME（建议：fw4 reload；检查 /etc/nftables.d include）"

  echo "$tables" | grep -q "^table inet fw4" \
    && ok "系统 fw4 表存在（未被污染）" \
    || fail "未发现 inet fw4（建议：立即回滚/重启防火墙，排查是否误 flush ruleset）"

  chain_out="$(nft list chain "$NFT_TABLE_FAMILY" "$NFT_TABLE_NAME" "$NFT_CHAIN_PREROUTING" 2>/dev/null)"
  if [ -z "$chain_out" ]; then
    fail "未能读取链：$NFT_TABLE_FAMILY $NFT_TABLE_NAME $NFT_CHAIN_PREROUTING（建议：nft -c -f 规则文件；fw4 print | nft -c -f -）"
  else
    cn_line="$(echo "$chain_out" | awk 'BEGIN{n=0;ans=0} {n++; if(ans==0 && $0 ~ /ip daddr @'"$NFT_SET_CN4"' return/){ans=n}} END{print ans}')"
    tp_line="$(echo "$chain_out" | awk 'BEGIN{n=0;ans=0} {n++; if(ans==0 && $0 ~ / tproxy /){ans=n}} END{print ans}')"

    [ "$cn_line" -gt 0 ] && ok "发现 CN 硬绕过：ip daddr @$NFT_SET_CN4 return（行号：$cn_line）" \
                         || fail "缺失 CN 硬绕过规则（建议：必须在 prerouting mangle 最前 return）"

    [ "$tp_line" -gt 0 ] && ok "发现 tproxy 规则（行号：$tp_line）" \
                         || warn "未发现 tproxy 规则（可能未启用透明引流；建议：确认 nftables 文件已被 fw4 include 并加载）"

    if [ "$cn_line" -gt 0 ] && [ "$tp_line" -gt 0 ]; then
      if [ "$cn_line" -lt "$tp_line" ]; then
        ok "强制验收通过：CN return 在 tproxy 前（$cn_line < $tp_line）"
      else
        fail "强制验收失败：CN return 在 tproxy 后（$cn_line >= $tp_line；建议：调整规则顺序，禁止 CN 进入 Xray）"
      fi
    fi
  fi

  set_out="$(nft list set "$NFT_TABLE_FAMILY" "$NFT_TABLE_NAME" "$NFT_SET_CN4" 2>/dev/null)"
  if [ -z "$set_out" ]; then
    fail "无法读取 CN 集合：$NFT_SET_CN4（建议：检查 cn4.nft 是否被 include；检查部署脚本生成）"
  else
    cnt="$(nft_set_count_elements "$set_out" 2>/dev/null | head -n 1)"
    case "$cnt" in
      ""|*[!0-9]*) warn "CN 集合元素数量解析失败（建议：手动 nft list set ... 查看 elements）" ;;
      *)
        [ "$cnt" -gt 0 ] && ok "CN 集合非空（元素数：$cnt）" \
                         || fail "CN 集合为空（$cnt；建议：重新生成 cn4.nft 并加载）"
      ;;
    esac
  fi
fi

log "--------------------------------------------"

#####################################
# 3/8 策略路由检查
#####################################
log "【3/8】策略路由检查（mark/table）"

if ! have_cmd ip; then
  fail "缺少 ip 命令"
else
  ip rule 2>/dev/null | grep -q "fwmark 0x1.*lookup 100" \
    && ok "存在：fwmark 0x1 lookup 100（TPROXY 回环）" \
    || fail "缺失：fwmark 0x1 lookup 100（建议：补 ip rule + table 100 local default dev lo）"

  t100="$(ip route show table 100 2>/dev/null)"
  echo "$t100" | grep -q "^local default dev lo" \
    && ok "table 100 正确：local default dev lo" \
    || fail "table 100 不正确（建议：ip route add local default dev lo table 100）"

  ip rule 2>/dev/null | grep -q "fwmark 0x2.*lookup 200" \
    && ok "存在：fwmark 0x2 lookup 200（wg0 出口策略）" \
    || fail "缺失：fwmark 0x2 lookup 200（建议：补 ip rule + table 200）"

  t200="$(ip route show table 200 2>/dev/null)"
  echo "$t200" | grep -q "^default dev $WG_IFACE" \
    && ok "table 200 默认路由：default dev $WG_IFACE" \
    || fail "table 200 缺少 default dev $WG_IFACE（建议：ip route add default dev wg0 table 200）"

  echo "$t200" | grep -q "^unreachable default" \
    && ok "table 200 兜底：unreachable default（wg0 掉线不会偷偷直连）" \
    || fail "table 200 缺少 unreachable default（建议：ip route add unreachable default table 200）"
fi

log "--------------------------------------------"

#####################################
# 4/8 dnsmasq 控制平面与 confdir 加载验证
#####################################
log "【4/8】dnsmasq 控制平面检查（含 confdir 加载验证）"

if [ ! -d "$DNSMASQ_DIR" ]; then
  fail "目录不存在：$DNSMASQ_DIR（建议：确认 confdir 是否启用）"
else
  grep -Rqs "^[[:space:]]*no-resolv" "$DNSMASQ_DIR"/*.conf 2>/dev/null \
    && ok "已设置 no-resolv（避免混用系统 resolv.conf）" \
    || fail "未发现 no-resolv（风险：DNS 泄漏/污染；建议：split.conf 加上 no-resolv）"

  grep -Rqs "^[[:space:]]*server=127\.0\.0\.1#$XRAY_DNS_PORT" "$DNSMASQ_DIR"/*.conf 2>/dev/null \
    && ok "默认上游指向 Xray DNS：127.0.0.1#$XRAY_DNS_PORT" \
    || fail "未发现 server=127.0.0.1#$XRAY_DNS_PORT（风险：非 CN DNS 不走 wg0；建议：split.conf 设默认上游）"

  # 运行时 confdir 检测
  loaded="0"
  for f in /tmp/etc/dnsmasq.conf.* /var/etc/dnsmasq.conf.* /tmp/dnsmasq.conf /var/dnsmasq.conf; do
    if [ -f "$f" ] && grep -qs "conf-dir=$DNSMASQ_DIR" "$f" 2>/dev/null; then
      loaded="1"
      ok "dnsmasq 运行时配置加载了 confdir：$f"
      break
    fi
  done
  [ "$loaded" = "0" ] && warn "未能确认 confdir 已加载（可能路径不同）。建议：logread -e dnsmasq | grep conf-dir；检查 /tmp/etc/dnsmasq.conf.*"
fi

log "--------------------------------------------"

#####################################
# 5/8 Xray 监听与 DNS detour（责任层定位增强）
#####################################
log "【5/8】Xray 监听与 DNS detour 检查（责任层定位）"

r1="$(is_listening_port any "$TPROXY_PORT"; echo $?)"
if [ "$r1" -eq 0 ]; then
  ok "Xray TPROXY 端口监听正常：:$TPROXY_PORT"
elif [ "$r1" -eq 2 ]; then
  warn "缺少 ss/netstat，无法确认 :$TPROXY_PORT 监听（建议：安装 ip-full 或 net-tools-netstat）"
else
  fail "未检测到 :$TPROXY_PORT 监听（建议：核对 inbound 端口与 nftables tproxy 端口一致；/etc/init.d/xray restart）"
fi

detour_ok="0"
if [ -d "$XRAY_DIR" ] && grep -Rqs "\"detour\"[[:space:]]*:[[:space:]]*\"wg0_out\"" "$XRAY_DIR" 2>/dev/null; then
  detour_ok="1"
fi

if [ "$detour_ok" = "1" ]; then
  ok "Xray 配置含 detour: wg0_out（符合：非 CN DNS/流量锁定 wg0）"
else
  fail "未发现 detour: wg0_out（风险：非 CN DNS 可能走主路由泄漏/污染；建议：Xray DNS servers 必须 detour wg0_out）"
  show_xray_dns_related
fi

if have_cmd xray; then
  if [ -f "$XRAY_DIR/config.json" ]; then
    if xray run -test -config "$XRAY_DIR/config.json" >/dev/null 2>&1; then
      ok "Xray 配置语法测试通过：xray run -test"
    else
      fail "Xray 配置语法测试失败（建议：xray run -test -config /etc/xray/config.json 查看具体错误）"
    fi
  else
    warn "未找到 $XRAY_DIR/config.json（建议：确认部署路径）"
  fi
else
  warn "未找到 xray 命令（建议：确认 xray-core 是否正确安装）"
fi

log "--------------------------------------------"

#####################################
# 6/8 运维级：DNS 功能性测试（nslookup）
#####################################
log "【6/8】DNS 功能性测试（证明 dnsmasq 控制面可用）"

dns_test_nslookup "$TEST_CN_DOMAIN" "CN"
dns_test_nslookup "$TEST_NONCN_DOMAIN" "非CN"

# 如果关键 DNS 项失败，附带定位 dnsmasq 配置片段
if [ "$FAIL" -gt 0 ]; then
  # 仅当 dnsmasq 相关的关键项疑似有问题时再输出（避免刷屏）
  if ! grep -Rqs "server=127\.0\.0\.1#$XRAY_DNS_PORT" "$DNSMASQ_DIR"/*.conf 2>/dev/null; then
    show_dnsmasq_related
  fi
fi

log "--------------------------------------------"

#####################################
# 7/8 抓包辅助验证（强证据链，可选）
#####################################
log "【7/8】抓包辅助验证（可选，强证据链）"
if [ "$CAPTURE" -eq 1 ]; then
  if ! have_cmd tcpdump; then
    warn "未安装 tcpdump，无法抓包（建议：opkg install tcpdump）"
  else
    log "提示：将进行三轮抓包，每轮 12 秒，请务必从“客户端”发起访问："
    log "  A) CN 站点：$TEST_CN_DOMAIN（期望：TPROXY 端口无报文）"
    log "  B) 非 CN：$TEST_NONCN_DOMAIN（期望：TPROXY 端口有报文）"
    log "  C) DNS 经 wg0（期望：wg0 上出现 port 53）"

    : > "$CN_CAP_FILE"
    log "抓包 A（12 秒）：tcpdump -ni any port $TPROXY_PORT"
    tcpdump -ni any "port $TPROXY_PORT" -c 200 >"$CN_CAP_FILE" 2>/dev/null &
    pid="$!"; sleep 12; kill "$pid" >/dev/null 2>&1
    cn_hits="$(wc -l <"$CN_CAP_FILE" 2>/dev/null | tr -d ' ')"; [ -z "$cn_hits" ] && cn_hits="0"
    [ "$cn_hits" -eq 0 ] && ok "抓包 A：TPROXY 无报文（符合：CN 不进 Xray）" \
                         || warn "抓包 A：TPROXY 捕获 $cn_hits 行（异常：可能 CN 进入 Xray；建议：复核 nft return 顺序与目标域名）"

    : > "$NONCN_CAP_FILE"
    log "抓包 B（12 秒）：tcpdump -ni any port $TPROXY_PORT"
    tcpdump -ni any "port $TPROXY_PORT" -c 200 >"$NONCN_CAP_FILE" 2>/dev/null &
    pid="$!"; sleep 12; kill "$pid" >/dev/null 2>&1
    noncn_hits="$(wc -l <"$NONCN_CAP_FILE" 2>/dev/null | tr -d ' ')"; [ -z "$noncn_hits" ] && noncn_hits="0"
    [ "$noncn_hits" -gt 0 ] && ok "抓包 B：TPROXY 有报文（符合：非 CN 进入 Xray）" \
                            || warn "抓包 B：TPROXY 无报文（异常：可能未引流/客户端未走旁路由；建议：检查客户端网关/DNS 设置与 nft tproxy 链）"

    : > "$DNSWG_CAP_FILE"
    log "抓包 C（12 秒）：tcpdump -ni $WG_IFACE port 53"
    tcpdump -ni "$WG_IFACE" "port 53" -c 200 >"$DNSWG_CAP_FILE" 2>/dev/null &
    pid="$!"; sleep 12; kill "$pid" >/dev/null 2>&1
    dns_hits="$(wc -l <"$DNSWG_CAP_FILE" 2>/dev/null | tr -d ' ')"; [ -z "$dns_hits" ] && dns_hits="0"
    [ "$dns_hits" -gt 0 ] && ok "抓包 C：wg0 上有 DNS（倾向：非 CN DNS 经 wg0）" \
                           || warn "抓包 C：wg0 上无 DNS（异常：DNS 可能未走 wg0；建议：检查 Xray DNS detour 与 table 200）"

    log "抓包原始文件：$CN_CAP_FILE / $NONCN_CAP_FILE / $DNSWG_CAP_FILE"
  fi
else
  ok "未启用抓包（如需强证据链：sh /root/selfcheck_splittunnel.sh --capture）"
fi

log "--------------------------------------------"

#####################################
# 8/8 最终判定与 JSON 摘要
#####################################
log "【8/8】自检摘要与上线判定"

if [ "$FAIL" -eq 0 ]; then
  ok "自检通过：未发现阻断上线的问题（FAIL=0，WARN=$WARN）"
  log "上线建议：允许上线。若存在 ⚠️ 项，建议按提示优化提升稳定性。"
else
  fail "自检未通过：发现 $FAIL 个阻断问题（WARN=$WARN）"
  log "上线建议：禁止上线，必须修复所有 ❌ 项后再验收。"
  log "快速排查命令："
  log "  1) nft 规则顺序：nft list chain $NFT_TABLE_FAMILY $NFT_TABLE_NAME $NFT_CHAIN_PREROUTING"
  log "  2) CN 集合：nft list set $NFT_TABLE_FAMILY $NFT_TABLE_NAME $NFT_SET_CN4"
  log "  3) 策略路由：ip rule; ip route show table 100; ip route show table 200"
  log "  4) dnsmasq：logread -e dnsmasq; netstat/ss 看 53 端口"
  log "  5) Xray：logread -e xray; xray run -test -config $XRAY_DIR/config.json"
fi

if [ "$JSON" -eq 1 ]; then
  status="PASS"
  [ "$FAIL" -ne 0 ] && status="FAIL"
  printf '{'
  printf '"status":"%s",' "$status"
  printf '"fail":%s,' "$FAIL"
  printf '"warn":%s,' "$WARN"
  printf '"wg_iface":"%s",' "$WG_IFACE"
  printf '"dns_test_cn":"%s",' "$TEST_CN_DOMAIN"
  printf '"dns_test_noncn":"%s"' "$TEST_NONCN_DOMAIN"
  printf '}\n'
fi

log "========== 自检结束 =========="

[ "$FAIL" -eq 0 ] && exit 0
exit 1
