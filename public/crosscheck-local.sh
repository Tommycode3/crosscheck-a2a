#!/usr/bin/env bash
# ============================================================================
#  CROSSCHECK · local security agent
#  The cloud scanner audits public things (A2A cards, web endpoints, DNS/TLS).
#  THIS runs on YOUR machine to check what only a local process can see:
#  WiFi security, firewall, listening ports, sharing services, DNS, LAN context.
#
#  SAFE BY DESIGN:
#   - read-only. it changes nothing.
#   - your machine only. it does NOT scan other people's devices on the network.
#   - private. nothing is uploaded anywhere; the report stays in your terminal.
#   - no sudo required (a couple of checks just show "limited" without it).
#
#  Review this script before running it (good security hygiene). Then:
#     bash crosscheck-local.sh
# ============================================================================
set -u
A="\033[38;5;43m"; B="\033[38;5;75m"; Y="\033[38;5;221m"; R="\033[38;5;203m"; G="\033[38;5;84m"; D="\033[2m"; N="\033[0m"
score=100; pass=0; warn=0; fail=0
P(){ echo -e "  ${G}✓ PASS${N}  $1"; pass=$((pass+1)); }
W(){ echo -e "  ${Y}▲ WARN${N}  $1"; [ -n "${2:-}" ] && echo -e "         ${D}→ $2${N}"; warn=$((warn+1)); score=$((score-${3:-6})); }
Fl(){ echo -e "  ${R}✗ FAIL${N}  $1"; [ -n "${2:-}" ] && echo -e "         ${D}→ $2${N}"; fail=$((fail+1)); score=$((score-${3:-15})); }
I(){ echo -e "  ${B}• info${N}  $1"; }
H(){ echo -e "\n${A}── $1 ──${N}"; }

OS="$(uname -s)"
echo -e "${A}╔══════════════════════════════════════════════╗"
echo -e "║   CROSSCHECK · local security agent           ║"
echo -e "║   read-only · your machine only · private     ║"
echo -e "╚══════════════════════════════════════════════╝${N}"
echo -e "${D}host: $(hostname) · os: $OS · $(date)${N}"

if [ "$OS" = "Darwin" ]; then
  # ---------------- WiFi ----------------
  H "WiFi"
  WIFI="$(system_profiler SPAirPortDataType 2>/dev/null)"
  SSID="$(echo "$WIFI" | awk '/Current Network Information:/{getline; gsub(/^[ \t]+|:$/,""); print; exit}')"
  SEC="$(echo "$WIFI" | awk '/Current Network Information:/{f=1} f&&/Security:/{sub(/.*Security: /,""); print; exit}')"
  if [ -n "$SSID" ]; then
    I "network: $SSID"
    case "$SEC" in
      *WPA3*) P "WiFi encryption: $SEC (strong)";;
      *WPA2*) P "WiFi encryption: $SEC";;
      *WPA*)  W "WiFi encryption: $SEC (WPA/TKIP is weak)" "Prefer WPA2/WPA3 networks." 8;;
      *WEP*)  Fl "WiFi encryption: WEP (broken)" "WEP is trivially cracked. Avoid this network." 20;;
      *None*|"") Fl "WiFi is OPEN / unencrypted ($SEC)" "Anyone nearby can sniff traffic. Use a VPN or avoid." 18;;
      *) I "WiFi security: $SEC";;
    esac
  else I "Not on WiFi (or info unavailable)."; fi

  # ---------------- Firewall ----------------
  H "Firewall"
  FW="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)"
  case "$FW" in
    *enabled*) P "Application firewall is ON";;
    *disabled*) Fl "Application firewall is OFF" "Enable it: System Settings → Network → Firewall." 12;;
    *) I "Firewall state unknown (may need permission).";;
  esac
  STEALTH="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)"
  case "$STEALTH" in *enabled*) P "Stealth mode ON (won't answer pings/port scans)";; *disabled*) W "Stealth mode OFF" "Turn on stealth mode to ignore probe traffic." 4;; esac

  # ---------------- Sharing services ----------------
  H "Sharing / remote access"
  SVC="$(launchctl list 2>/dev/null)"
  chk(){ echo "$SVC" | grep -q "$1" && Fl "$2 is RUNNING" "$3" "${4:-10}" || P "$2 off"; }
  chk "com.openssh.sshd" "Remote Login (SSH)" "Disable if unused: System Settings → General → Sharing." 8
  chk "com.apple.screensharing" "Screen Sharing" "Disable if unused (Sharing settings)." 8
  chk "com.apple.smbd" "File Sharing (SMB)" "Disable if unused (Sharing settings)." 6

  # ---------------- Listening ports ----------------
  H "Listening services (this machine)"
  LIST="$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1, $9}' | sort -u)"
  EXT="$(echo "$LIST" | grep -vE '127\.0\.0\.1|\[::1\]|localhost' | grep -E '\*:|0\.0\.0\.0' )"
  if [ -z "$LIST" ]; then I "No listing (run with sudo for the full picture)."; else
    NL=$(echo "$LIST" | grep -c .)
    I "$NL listening sockets total"
    if [ -n "$EXT" ]; then
      W "$(echo "$EXT" | grep -c .) service(s) listening on ALL interfaces" "Bind to 127.0.0.1 unless they must be public." 8
      echo "$EXT" | head -6 | sed 's/^/         /'
    else P "No services exposed on all interfaces"; fi
  fi

  # ---------------- DNS ----------------
  H "DNS"
  NS="$(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/{print $3; exit}')"
  [ -n "$NS" ] && I "Primary resolver: $NS"
  echo "$NS" | grep -qE '^(1\.1\.1\.1|8\.8\.8\.8|9\.9\.9\.9)$' && I "Using a public resolver." || true

  # ---------------- LAN context (passive) ----------------
  H "Local network (passive)"
  GW="$(netstat -rn 2>/dev/null | awk '/^default/{print $2; exit}')"
  IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)"
  [ -n "$IP" ] && I "Your IP: $IP   gateway: ${GW:-?}"
  NB=$(arp -a 2>/dev/null | grep -c "at ")
  I "$NB device(s) seen in the local ARP cache (neighbors already known to your Mac)"
  echo -e "         ${D}(passive read of the ARP cache — no active scan of others)${N}"

  # ---------------- System integrity ----------------
  H "System integrity"
  csrutil status 2>/dev/null | grep -q enabled && P "SIP (System Integrity Protection) enabled" || W "SIP disabled" "Re-enable unless you have a reason." 6

else
  H "Linux"
  I "macOS checks shown above are skipped; basic Linux checks:"
  command -v nmcli >/dev/null && { SEC="$(nmcli -t -f active,security dev wifi 2>/dev/null | awk -F: '/^yes/{print $2}')"; [ -n "$SEC" ] && I "WiFi security: $SEC"; }
  command -v ss >/dev/null && { N=$(ss -tlnH 2>/dev/null | grep -cE '0\.0\.0\.0|\*:'); [ "$N" -gt 0 ] && W "$N service(s) listening on all interfaces" "Bind to localhost where possible." 8 || P "No services on all interfaces"; }
  command -v ufw >/dev/null && { ufw status 2>/dev/null | grep -q active && P "ufw firewall active" || W "ufw inactive" "Enable a firewall." 10; }
fi

# ---------------- verdict ----------------
[ $score -lt 0 ] && score=0
GR="F"; [ $score -ge 60 ] && GR="D"; [ $score -ge 72 ] && GR="C"; [ $score -ge 82 ] && GR="B"; [ $score -ge 92 ] && GR="A"
echo -e "\n${A}══════════════════════════════════════════════${N}"
echo -e "  CROSSCHECK local score: ${A}$score/100 · grade $GR${N}   ${D}($pass pass · $warn warn · $fail fail)${N}"
echo -e "  full agent web auditor: ${B}https://crosstalk-agent.vercel.app${N}"
echo -e "${A}══════════════════════════════════════════════${N}\n"
