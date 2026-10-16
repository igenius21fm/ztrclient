#!/usr/bin/env bash
# macOS installer for the ZTRelay plugin wrappers (ztr_ssh, ztr_forward,
# ztr_pg, ztr_ferry — the launcher for the Ferry file manager — and ztr_proxy,
# the launcher for the browser-proxy window) so they run from anywhere,
# without a manual shell alias per
# docs/ztrclient's "Alias it" sections. Does NOT touch the platform or
# ztrClient.py itself — this is scoped to plugins/ only (which is also
# where ztr_tunnel_lp.py, ztr_dashboard.py, ztr_https.py, and ztr_requests/
# live). macOS/launchd only; Linux has its own installer-linux.sh.
#
#   ./installer-macos.sh                       install wrappers into ~/.local/bin
#   ./installer-macos.sh --prefix DIR          install into DIR instead
#   ./installer-macos.sh --venv-dir DIR        put ztr's own Python venv at DIR instead of ~/.local/share/ztr/ztr_venv
#   ./installer-macos.sh --with-service        also set up ztr_tunnel_lp.py as a launchd user agent
#   ./installer-macos.sh --with-dashboard      also set up ztr_dashboard.py as a launchd user agent
#   ./installer-macos.sh --with-requests       also set up ztr_requests (request-composer web UI) as a launchd user agent
#   ./installer-macos.sh --with-ferry          also add Ferry (the file manager) to your Applications, and check what it needs
#   ./installer-macos.sh --with-proxy          also add ZTR Proxy (the browser-proxy window) to your Applications, and check what it needs
#   ./installer-macos.sh --with-local-ip       also set up a dedicated loopback address for tunneled sessions
#   ./installer-macos.sh --local-ip IP         use IP instead of the default 10.10.15.10
#   ./installer-macos.sh --uninstall           remove the installed wrappers (agents, venv, and loopback address, if present)
#
# Run with no flags in an actual terminal and it just asks: whether to set
# up each service, whether to add Ferry and ZTR Proxy to your Applications,
# and (if any of the three services, or if --with-local-ip was passed) what
# IP to use. --with-service/--with-dashboard/--with-requests/--with-ferry/
# --with-proxy/--with-local-ip/--local-ip above are for skipping those prompts —
# non-interactive runs (CI, provisioning scripts, piped input) skip them
# automatically and just take the flags/defaults given.
#
# What it actually does:
#   1. Makes plugins/{ztr_ssh,ztr_forward,ztr_pg,ztr_ferry,ztr_proxy/ztr_proxy,ztr_fleet/ztr_fleet} executable — a zip
#      download doesn't reliably preserve the executable bit, so this
#      isn't just belt-and-suspenders.
#   2. Looks for a Python 3.12 or newer (ztrClient.py needs it — the python3
#      Apple ships is older; Homebrew's or python.org's will do, or set
#      ZTR_PYTHON to the one you want), then creates a dedicated venv for ztr
#      (default ~/.local/share/ztr/ztr_venv) if one isn't already there, and
#      installs pycryptodome into it — ztr_tunnel_lp.py imports RelayClient
#      from ztrClient.py, which needs it. Keeping this in its own venv
#      instead of the system or Homebrew site-packages means it can't clash
#      with whatever else is installed on your python3. All three launchd
#      agents (--with-service, --with-dashboard, --with-requests) run using
#      this venv's interpreter. With --with-dashboard, also installs scapy
#      into it — only needed for the dashboard's live traffic panel. With
#      --with-requests, also installs Pillow — ztr_requests/server.py needs
#      it to sniff/decode image responses.
#   3. Symlinks the wrappers into --prefix (default ~/.local/bin),
#      so `ztr_ssh`/`ztr_forward`/`ztr_pg`/`ztr_ferry`/`ztr_proxy`/`ztr_fleet` work from any shell, not just
#      one with a hand-edited rc file. Re-running just refreshes the links.
#   4. With --with-local-ip: adds --local-ip (default 10.10.15.10) as an
#      extra address on the loopback interface (`ifconfig lo0 alias`), so
#      ztr_tunnel_lp.py's per-session listeners (and the dashboard/requests
#      UI, if you set either up) have a dedicated address to bind to instead
#      of the generic 127.0.0.1 — needs sudo, requires you to run this
#      yourself. macOS has no dummy network interfaces, so unlike Linux this
#      is a loopback alias rather than its own interface. Also installs a
#      system-level launchd daemon (net.ztrelay.loopback-alias) that
#      re-adds the address on every boot, so this survives a reboot without
#      you having to re-run anything.
#   5. With --with-service: installs ztr_tunnel_lp.py as a launchd user
#      agent, prompting for your .ztr config path.
#   6. With --with-dashboard: installs ztr_dashboard.py as a launchd user
#      agent the same way — reuses the .ztr config from --with-service
#      above if you set both up together, otherwise prompts for its own
#      (or none, if you just want the tunnel/error panels).
#   7. With --with-requests: installs ztr_requests/server.py (a small
#      Postman-style web UI for firing one-off requests through an
#      authorized tunnel) as a launchd user agent, on the same loopback
#      address as the dashboard when --with-local-ip is set (else
#      127.0.0.1) — deliberately not the open LAN, since a request built
#      there can carry a route's real identifier/secret_key-backed tunnel.
#      No route config needed up front; it picks one per request from
#      whatever's in routes/.
#   8. With --with-ferry or --with-proxy: checks that the Python it set up
#      has Tk 8.6 or newer for the window (Apple's and Homebrew's default
#      python3 don't — it tells you the `brew install python-tk@X.Y` line,
#      or use the python.org installer, which includes Tk) and puts Ferry.app
#      / "ZTR Proxy.app" in ~/Applications, so they open from Launchpad and
#      Spotlight like any other app. `ztr_ferry` and `ztr_proxy` from a
#      terminal work either way (`ztr_proxy --cli` runs the proxy without a
#      window).
#
# Agent logs go to ~/Library/Logs/ztr/<name>.log; Ferry's and ZTR Proxy's go
# to ferry.log and proxy.log in the same folder.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGINS_DIR="$SCRIPT_DIR/plugins"
WRAPPERS=(ztr_ssh ztr_forward ztr_pg ztr_ferry ztr_proxy ztr_fleet)

# Where a wrapper's launcher script lives. Most sit directly in plugins/;
# ZTR Proxy and ZTR Fleet keep all of their files in their own folders.
wrapper_path() {
  case "$1" in
    ztr_proxy) echo "$PLUGINS_DIR/ztr_proxy/ztr_proxy" ;;
    ztr_fleet) echo "$PLUGINS_DIR/ztr_fleet/ztr_fleet" ;;
    *) echo "$PLUGINS_DIR/$1" ;;
  esac
}

PREFIX="${PREFIX:-$HOME/.local/bin}"
VENV_DIR="${VENV_DIR:-$HOME/.local/share/ztr/ztr_venv}"
LOCAL_IP="${LOCAL_IP:-10.10.15.10}"
LOCAL_IP_SET_BY_USER=0
WITH_SERVICE=0
WITH_SERVICE_SET_BY_USER=0
WITH_DASHBOARD=0
WITH_DASHBOARD_SET_BY_USER=0
WITH_REQUESTS=0
WITH_REQUESTS_SET_BY_USER=0
WITH_FERRY=0
WITH_FERRY_SET_BY_USER=0
WITH_PROXY=0
WITH_PROXY_SET_BY_USER=0
WITH_LOCAL_IP=0
UNINSTALL=0
ZTR_CONFIG_NAME=""
SCAPY_READY=0

if [[ -t 1 ]]; then
  C_INFO=$'\033[0;36m'; C_OK=$'\033[0;32m'; C_ERR=$'\033[0;31m'
  C_WARN=$'\033[0;33m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
  C_INFO=""; C_OK=""; C_ERR=""; C_WARN=""; C_DIM=""; C_RESET=""
fi
log_info() { echo "${C_INFO}[installer]${C_RESET} $*"; }
log_ok()   { echo "${C_OK}[installer]${C_RESET} $*"; }
log_warn() { echo "${C_WARN}[installer]${C_RESET} $*"; }
log_err()  { echo "${C_ERR}[installer] $*${C_RESET}" >&2; }

# Prints the leading comment block (everything up to the first non-comment
# line) with the "# " prefix stripped.
usage() {
  awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --venv-dir)
      VENV_DIR="$2"
      shift 2
      ;;
    --with-service)
      WITH_SERVICE=1
      WITH_SERVICE_SET_BY_USER=1
      shift
      ;;
    --with-dashboard)
      WITH_DASHBOARD=1
      WITH_DASHBOARD_SET_BY_USER=1
      shift
      ;;
    --with-requests)
      WITH_REQUESTS=1
      WITH_REQUESTS_SET_BY_USER=1
      shift
      ;;
    --with-ferry)
      WITH_FERRY=1
      WITH_FERRY_SET_BY_USER=1
      shift
      ;;
    --with-proxy)
      WITH_PROXY=1
      WITH_PROXY_SET_BY_USER=1
      shift
      ;;
    --with-local-ip)
      WITH_LOCAL_IP=1
      shift
      ;;
    --local-ip)
      LOCAL_IP="$2"
      LOCAL_IP_SET_BY_USER=1
      shift 2
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log_err "unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  log_err "this installer is for macOS — on Linux, use installer-linux.sh instead."
  exit 1
fi

LOG_DIR="$HOME/Library/Logs/ztr"
AGENT_DIR="$HOME/Library/LaunchAgents"
SERVICE_LABEL="net.ztrelay.tunnel-lp"
DASHBOARD_LABEL="net.ztrelay.dashboard"
REQUESTS_LABEL="net.ztrelay.requests"
SERVICE_UNIT="$AGENT_DIR/$SERVICE_LABEL.plist"
DASHBOARD_SERVICE_UNIT="$AGENT_DIR/$DASHBOARD_LABEL.plist"
REQUESTS_SERVICE_UNIT="$AGENT_DIR/$REQUESTS_LABEL.plist"
LO_IF="lo0"
LOOPBACK_DAEMON_LABEL="net.ztrelay.loopback-alias"
LOOPBACK_DAEMON_UNIT="/Library/LaunchDaemons/$LOOPBACK_DAEMON_LABEL.plist"
APPS_DIR="$HOME/Applications"
FERRY_APP="$APPS_DIR/Ferry.app"
PROXY_APP="$APPS_DIR/ZTR Proxy.app"

# Ask up front rather than requiring you to already know the flag exists —
# only when you didn't already say one way or the other with --with-service,
# and only when actually running interactively (skip in scripts/CI, and
# skip entirely for --uninstall, which doesn't need this).
if [[ "$WITH_SERVICE_SET_BY_USER" -eq 0 && "$UNINSTALL" -eq 0 && -t 0 ]]; then
  read -r -p "Set up ztr_tunnel_lp.py as a persistent launchd user agent? [y/N]: " WITH_SERVICE_ANSWER
  case "$WITH_SERVICE_ANSWER" in
    [yY]*) WITH_SERVICE=1 ;;
  esac
fi

# Same idea, asked separately — the dashboard doesn't need the tunnel
# service (or vice versa), so answering one shouldn't silently decide the
# other.
if [[ "$WITH_DASHBOARD_SET_BY_USER" -eq 0 && "$UNINSTALL" -eq 0 && -t 0 ]]; then
  read -r -p "Set up ztr_dashboard.py as a persistent launchd user agent? [y/N]: " WITH_DASHBOARD_ANSWER
  case "$WITH_DASHBOARD_ANSWER" in
    [yY]*) WITH_DASHBOARD=1 ;;
  esac
fi

# Same idea again — a separate yes/no, not folded into the dashboard
# prompt, since you might want the request UI without the dashboard or
# vice versa.
if [[ "$WITH_REQUESTS_SET_BY_USER" -eq 0 && "$UNINSTALL" -eq 0 && -t 0 ]]; then
  read -r -p "Set up ztr_requests (Postman-style request UI) as a persistent launchd user agent? [y/N]: " WITH_REQUESTS_ANSWER
  case "$WITH_REQUESTS_ANSWER" in
    [yY]*) WITH_REQUESTS=1 ;;
  esac
fi

# Ferry and ZTR Proxy are windows, so each is a plain yes/no of its own —
# they work with or without the services above.
if [[ "$WITH_FERRY_SET_BY_USER" -eq 0 && "$UNINSTALL" -eq 0 && -t 0 ]]; then
  read -r -p "Add Ferry (the file manager) to your Applications? [y/N]: " WITH_FERRY_ANSWER
  case "$WITH_FERRY_ANSWER" in
    [yY]*) WITH_FERRY=1 ;;
  esac
fi
if [[ "$WITH_PROXY_SET_BY_USER" -eq 0 && "$UNINSTALL" -eq 0 && -t 0 ]]; then
  read -r -p "Add ZTR Proxy (the browser-proxy window) to your Applications? [y/N]: " WITH_PROXY_ANSWER
  case "$WITH_PROXY_ANSWER" in
    [yY]*) WITH_PROXY=1 ;;
  esac
fi

# The service is useless without somewhere to bind its per-session
# listeners — without the loopback address, every session fails to start
# the moment the service is actually up. So --with-service (flag or the
# prompt above) implies --with-local-ip, not just the "what IP" prompt
# below — this is what actually adds the address later on.
if [[ "$WITH_SERVICE" -eq 1 ]]; then
  WITH_LOCAL_IP=1
fi

# Ask rather than silently defaulting — this address matters (it's what
# ztr_tunnel_lp.py binds to and every wrapper connects through), so
# anyone with a reason to pick their own subnet should get the chance
# before it's baked into a launchd plist. Only asks if --local-ip wasn't
# already given, and only when actually running interactively (skip in
# scripts/CI, where stdin isn't a terminal — reading from it there would
# either hang or consume unrelated piped input).
if [[ "$LOCAL_IP_SET_BY_USER" -eq 0 && ( "$WITH_LOCAL_IP" -eq 1 || "$WITH_SERVICE" -eq 1 ) && -t 0 ]]; then
  read -r -p "Loopback IP for tunneled sessions to bind to [$LOCAL_IP]: " LOCAL_IP_INPUT
  if [[ -n "$LOCAL_IP_INPUT" ]]; then
    LOCAL_IP="$LOCAL_IP_INPUT"
  fi
fi

# This value ends up in `ifconfig` and a root-owned launchd plist, so it
# has to be a plain dotted-quad address — nothing else gets through.
IPV4_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
if [[ "$UNINSTALL" -eq 0 ]]; then
  octets_ok=1
  if [[ "$LOCAL_IP" =~ $IPV4_RE ]]; then
    IFS=. read -r o1 o2 o3 o4 <<< "$LOCAL_IP"
    for o in "$o1" "$o2" "$o3" "$o4"; do
      (( 10#$o > 255 )) && octets_ok=0
    done
  else
    octets_ok=0
  fi
  if [[ "$octets_ok" -eq 0 ]]; then
    log_err "'$LOCAL_IP' isn't a valid IPv4 address — pass something like --local-ip 10.10.15.10."
    exit 1
  fi
  # 127.0.0.1 is lo0's own address, so there's nothing to alias — the
  # services just bind to it directly.
  if [[ "$LOCAL_IP" == "127.0.0.1" && "$WITH_LOCAL_IP" -eq 1 ]]; then
    log_info "127.0.0.1 is already the loopback address — skipping the alias setup, services will bind to it directly."
    WITH_LOCAL_IP=0
  fi
fi

# ---------------------------------------------------------------------------
# Loopback-alias helpers — macOS can't create dummy interfaces, so the
# dedicated address is an alias on lo0 instead. Made persistent by
# $LOOPBACK_DAEMON_UNIT, a system-level (not per-user) launchd daemon that
# re-adds it at boot — see the --with-local-ip block below.

local_ip_present() {
  ifconfig "$LO_IF" 2>/dev/null | grep -qF "inet ${LOCAL_IP} "
}

# The address our boot daemon was installed with, if any — read back from
# the plist so uninstall removes the right one even if you used --local-ip
# at install time and not now.
daemon_alias_ip() {
  [[ -f "$LOOPBACK_DAEMON_UNIT" ]] || return 0
  /usr/libexec/PlistBuddy -c "Print :ProgramArguments:3" "$LOOPBACK_DAEMON_UNIT" 2>/dev/null || true
}

remove_alias_ip() {
  [[ -n "$1" ]] || return 0
  # 127.0.0.1 is lo0's own address, not an alias we added — removing it
  # would break all local networking.
  [[ "$1" != "127.0.0.1" ]] || return 0
  sudo ifconfig "$LO_IF" -alias "$1" >/dev/null 2>&1 || true
}

# zsh -> ~/.zshrc (macOS's default shell); bash -> ~/.bash_profile (Terminal
# opens login shells, which read that rather than ~/.bashrc); anything else
# -> ~/.profile. Defined up here (not just near where it's used) so
# uninstall() — which runs and exits before the rest of the script — can use
# it too.
detect_rc_file() {
  case "$(basename "${SHELL:-}")" in
    zsh) echo "$HOME/.zshrc" ;;
    bash) echo "$HOME/.bash_profile" ;;
    *) echo "$HOME/.profile" ;;
  esac
}

# ---------------------------------------------------------------------------
# Python and app-bundle helpers.

# ztrClient.py uses syntax from Python 3.12, so that is the oldest this can use.
py_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1; }
# Ferry's and ZTR Proxy's windows need Tk 8.6 or newer (Apple's built-in Python has 8.5).
py_has_tk() { "$1" -c 'import sys, tkinter; sys.exit(0 if tkinter.TkVersion >= 8.6 else 1)' >/dev/null 2>&1; }

# find_python WANT_TK: prints a Python 3.12+ — with a usable Tk if WANT_TK is 1 and
# one exists, otherwise any. ZTR_PYTHON picks one outright. Returns 1 if there is none.
find_python() {
  local want_tk="$1" candidate best="" found
  for candidate in "${ZTR_PYTHON:-}" python3 python3.14 python3.13 python3.12 \
      /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 \
      /usr/local/bin/python3.14 /usr/local/bin/python3.13 /usr/local/bin/python3.12 \
      /Library/Frameworks/Python.framework/Versions/Current/bin/python3; do
    [[ -n "$candidate" ]] || continue
    found="$(command -v "$candidate" 2>/dev/null || true)"
    [[ -n "$found" ]] || continue
    # Without the Xcode command line tools /usr/bin/python3 is a stub that pops up an install dialog.
    if [[ "$found" == /usr/bin/python3 ]] && ! xcode-select -p >/dev/null 2>&1; then
      continue
    fi
    py_ok "$found" || continue
    if [[ "$want_tk" -eq 0 ]] || py_has_tk "$found"; then
      echo "$found"
      return 0
    fi
    [[ -n "$best" ]] || best="$found"
  done
  [[ -n "$best" ]] || return 1
  echo "$best"
}

# make_icns PNG OUT.icns — builds the icon file an app bundle uses from a square PNG.
make_icns() {
  local png="$1" out="$2" set size
  set="$(mktemp -d -t ztr_icon)/AppIcon.iconset"
  mkdir -p "$set"
  for size in 16 32 64 128; do
    sips -z "$size" "$size" "$png" --out "$set/icon_${size}x${size}.png" >/dev/null 2>&1 || return 1
  done
  cp "$set/icon_32x32.png" "$set/icon_16x16@2x.png"
  cp "$set/icon_64x64.png" "$set/icon_32x32@2x.png"
  cp "$set/icon_128x128.png" "$set/icon_128x128@2x.png" 2>/dev/null || true
  rm -f "$set/icon_64x64.png"
  iconutil -c icns "$set" -o "$out" >/dev/null 2>&1
  local status=$?
  rm -rf "$(dirname "$set")"
  return "$status"
}

# make_app_bundle APP NAME BUNDLE_ID LAUNCHER ICON_PNG LOGNAME — a small app that just runs
# the launcher in the foreground, so Ferry / ZTR Proxy open from Launchpad and Spotlight.
# Anything it prints goes to ~/Library/Logs/ztr/LOGNAME.log, since an app has no terminal.
make_app_bundle() {
  local app="$1" name="$2" bundle_id="$3" launcher="$4" png="$5" logname="$6"
  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0">'
    echo '<dict>'
    echo "  <key>CFBundleName</key><string>$(xml_escape "$name")</string>"
    echo "  <key>CFBundleDisplayName</key><string>$(xml_escape "$name")</string>"
    echo "  <key>CFBundleIdentifier</key><string>$(xml_escape "$bundle_id")</string>"
    echo '  <key>CFBundleExecutable</key><string>launch</string>'
    echo '  <key>CFBundleIconFile</key><string>AppIcon</string>'
    echo '  <key>CFBundlePackageType</key><string>APPL</string>'
    echo '  <key>CFBundleVersion</key><string>1</string>'
    echo '  <key>LSMinimumSystemVersion</key><string>10.13</string>'
    echo '  <key>NSHighResolutionCapable</key><true/>'
    echo '</dict>'
    echo '</plist>'
  } > "$app/Contents/Info.plist"
  {
    echo '#!/bin/bash'
    echo "# written by the ztrclient installer (--uninstall removes this app)"
    echo "export ZTR_VENV_DIR=$(printf '%q' "$VENV_DIR")"
    echo "mkdir -p $(printf '%q' "$LOG_DIR")"
    echo "exec $(printf '%q' "$launcher") --foreground >> $(printf '%q' "$LOG_DIR/$logname.log") 2>&1"
  } > "$app/Contents/MacOS/launch"
  chmod +x "$app/Contents/MacOS/launch"
  : > "$app/Contents/Resources/.ztrclient-installer"
  make_icns "$png" "$app/Contents/Resources/AppIcon.icns" || log_warn "couldn't build $name's icon — the app will have the default one."
  plutil -lint "$app/Contents/Info.plist" >/dev/null
}

# Removes an app bundle, but only one this installer wrote.
remove_app_bundle() {
  local app="$1" name="$2"
  if [[ -f "$app/Contents/Resources/.ztrclient-installer" ]]; then
    rm -rf "$app"
    log_ok "$name removed from $APPS_DIR."
  fi
}

# ---------------------------------------------------------------------------
# launchd helpers. A user agent lives in the "gui/<uid>" domain when you're
# logged in at the console, or "user/<uid>" over SSH with no GUI session —
# pick whichever one this account actually has.

launchd_domain() {
  local uid
  uid="$(id -u)"
  if launchctl print "gui/$uid" >/dev/null 2>&1; then
    echo "gui/$uid"
  elif launchctl print "user/$uid" >/dev/null 2>&1; then
    echo "user/$uid"
  else
    return 1
  fi
}

xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# write_agent_plist PLIST LABEL LOGNAME ARG...
# Restarts only after a failure exit (same as Restart=on-failure under
# systemd). PYTHONUNBUFFERED so prints reach the log file as they happen.
write_agent_plist() {
  local plist="$1" label="$2" logname="$3"
  shift 3
  mkdir -p "$AGENT_DIR" "$LOG_DIR"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0">'
    echo '<dict>'
    echo "  <key>Label</key><string>$(xml_escape "$label")</string>"
    echo '  <key>ProgramArguments</key>'
    echo '  <array>'
    local arg
    for arg in "$@"; do
      echo "    <string>$(xml_escape "$arg")</string>"
    done
    echo '  </array>'
    echo "  <key>WorkingDirectory</key><string>$(xml_escape "$SCRIPT_DIR")</string>"
    echo '  <key>EnvironmentVariables</key>'
    echo '  <dict><key>PYTHONUNBUFFERED</key><string>1</string></dict>'
    echo '  <key>RunAtLoad</key><true/>'
    echo '  <key>KeepAlive</key>'
    echo '  <dict><key>SuccessfulExit</key><false/></dict>'
    echo "  <key>StandardOutPath</key><string>$(xml_escape "$LOG_DIR/$logname.log")</string>"
    echo "  <key>StandardErrorPath</key><string>$(xml_escape "$LOG_DIR/$logname.log")</string>"
    echo '</dict>'
    echo '</plist>'
  } > "$plist"
  plutil -lint "$plist" >/dev/null
}

# Replaces any already-loaded copy, then loads and starts the agent. A
# bootstrap right after a bootout can briefly fail with an I/O error while
# launchd finishes tearing the old one down, so it retries a few times.
load_agent() {
  local label="$1" plist="$2" domain tries=0
  domain="$(launchd_domain)" || return 1
  launchctl bootout "$domain/$label" >/dev/null 2>&1 || true
  until launchctl bootstrap "$domain" "$plist" 2>/dev/null; do
    tries=$((tries + 1))
    if [[ "$tries" -ge 5 ]]; then
      launchctl bootstrap "$domain" "$plist"
      return $?
    fi
    sleep 1
  done
  launchctl enable "$domain/$label" >/dev/null 2>&1 || true
}

unload_agent() {
  local label="$1" uid
  uid="$(id -u)"
  launchctl bootout "gui/$uid/$label" >/dev/null 2>&1 || true
  launchctl bootout "user/$uid/$label" >/dev/null 2>&1 || true
}

# Prints the launchctl hints shown after an agent starts.
agent_hints() {
  local label="$1" logname="$2"
  echo "${C_DIM}    launchctl print $(launchd_domain)/$label${C_RESET}"
  echo "${C_DIM}    tail -f $LOG_DIR/$logname.log${C_RESET}"
}

no_launchd_help() {
  local flag="$1" standalone="$2"
  log_err "no launchd user session available for this account."
  log_warn "if you reached this shell via su/sudo into this user: log in directly as them instead (Terminal"
  log_warn "or SSH) and re-run. If launchd can't run agents here at all, $flag can't work — run it yourself"
  log_warn "instead, in the foreground:"
  log_warn "    $standalone"
}

# ---------------------------------------------------------------------------
uninstall() {
  log_info "removing wrappers from $PREFIX ..."
  local removed=0
  for name in "${WRAPPERS[@]}"; do
    local link="$PREFIX/$name"
    # Only remove it if it's actually our symlink — never clobber some
    # unrelated file that happens to share the name.
    if [[ -L "$link" ]] && [[ "$(readlink "$link")" == "$(wrapper_path "$name")" ]]; then
      rm -f "$link"
      removed=1
    fi
  done
  if [[ "$removed" -eq 1 ]]; then
    log_ok "wrappers removed."
  else
    log_warn "no installed wrappers found in $PREFIX."
  fi

  remove_app_bundle "$FERRY_APP" "Ferry"
  remove_app_bundle "$PROXY_APP" "ZTR Proxy"

  local label unit
  for pair in "$SERVICE_LABEL:$SERVICE_UNIT" "$DASHBOARD_LABEL:$DASHBOARD_SERVICE_UNIT" "$REQUESTS_LABEL:$REQUESTS_SERVICE_UNIT"; do
    label="${pair%%:*}"
    unit="${pair#*:}"
    if [[ -f "$unit" ]]; then
      log_info "stopping and removing the $label launchd agent ..."
      unload_agent "$label"
      rm -f "$unit"
      log_ok "agent removed."
    fi
  done

  if [[ -d "$LOG_DIR" ]]; then
    rm -rf "$LOG_DIR"
  fi

  if [[ -d "$VENV_DIR" ]]; then
    log_info "removing ztr's venv at $VENV_DIR ..."
    rm -rf "$VENV_DIR"
    log_ok "venv removed."
  fi

  local rc_file
  rc_file="$(detect_rc_file)"
  local path_line="export PATH=\"$PREFIX:\$PATH\"  # added by ztrclient installer"
  if [[ -f "$rc_file" ]] && grep -qF "# added by ztrclient installer" "$rc_file" 2>/dev/null; then
    log_info "removing the PATH export and aliases we added to $rc_file ..."
    local tmp_rc
    tmp_rc="$(mktemp -t ztr_rc)"
    grep -vxF "$path_line" "$rc_file" > "$tmp_rc" || true
    for name in "${WRAPPERS[@]}"; do
      local alias_line="alias $name=\"$(wrapper_path "$name")\"  # added by ztrclient installer"
      grep -vxF "$alias_line" "$tmp_rc" > "$tmp_rc.next" || true
      mv "$tmp_rc.next" "$tmp_rc"
    done
    local venv_alias_line="alias ztr_venv=\"source $VENV_DIR/bin/activate\"  # added by ztrclient installer"
    grep -vxF "$venv_alias_line" "$tmp_rc" > "$tmp_rc.next" || true
    mv "$tmp_rc.next" "$tmp_rc"
    cat "$tmp_rc" > "$rc_file"
    rm -f "$tmp_rc"
    log_ok "removed from $rc_file."
  fi

  local daemon_ip
  daemon_ip="$(daemon_alias_ip)"
  if [[ -f "$LOOPBACK_DAEMON_UNIT" ]]; then
    log_info "removing the $LOOPBACK_DAEMON_LABEL boot daemon (needs sudo) ..."
    sudo launchctl bootout "system/$LOOPBACK_DAEMON_LABEL" >/dev/null 2>&1 || true
    sudo rm -f "$LOOPBACK_DAEMON_UNIT"
    log_ok "boot daemon removed."
  fi

  # The address the daemon was installed with, plus whatever --local-ip /
  # the default points at now — whichever of them are actually on lo0.
  local ip
  for ip in "$daemon_ip" "$LOCAL_IP"; do
    [[ -n "$ip" && "$ip" != "127.0.0.1" ]] || continue
    if ifconfig "$LO_IF" 2>/dev/null | grep -qF "inet $ip "; then
      log_info "removing $ip from $LO_IF (needs sudo) ..."
      remove_alias_ip "$ip"
      if ifconfig "$LO_IF" 2>/dev/null | grep -qF "inet $ip "; then
        log_warn "couldn't confirm $ip was removed from $LO_IF — remove it yourself: sudo ifconfig $LO_IF -alias $ip"
      else
        log_ok "$ip removed from $LO_IF."
      fi
    fi
  done
  exit 0
}
[[ "$UNINSTALL" -eq 1 ]] && uninstall

# ---------------------------------------------------------------------------
# Run as yourself, not root — an easy mistake when a command is habitually
# prefixed with sudo. Under `sudo ./installer-macos.sh`, $HOME can be root's
# (or this user's, depending on sudo's config), so the venv, wrapper symlinks
# and LaunchAgents can land in the wrong place, and launchctl would target
# root's session instead of yours. The few commands that do need privilege
# (--with-local-ip's loopback address and its boot daemon) already call sudo
# themselves, just for that piece.
if [[ "$(id -u)" -eq 0 ]] && [[ -z "${ZTR_ALLOW_ROOT:-}" ]]; then
  log_err "running as root (or via sudo) — re-run this as your normal user instead, without sudo."
  log_warn "it'll prompt for your password itself on the one part that actually needs it"
  log_warn "(--with-local-ip's loopback address). If you really do mean to install this"
  log_warn "for root specifically, set ZTR_ALLOW_ROOT=1 to skip this check."
  exit 1
fi

log_info "checking prerequisites ..."

WANT_TK=0
[[ "$WITH_FERRY" -eq 1 || "$WITH_PROXY" -eq 1 ]] && WANT_TK=1

VENV_PY="$VENV_DIR/bin/python3"
if [[ -x "$VENV_PY" ]]; then
  log_ok "ztr venv already exists at $VENV_DIR."
  if ! py_ok "$VENV_PY"; then
    log_warn "that venv's Python is older than 3.12, which ztrClient.py needs. Remove it (rm -rf $VENV_DIR) and re-run to rebuild it with a newer Python."
  fi
else
  # `command -v` alone isn't enough on a Mac: without the Xcode command line
  # tools, /usr/bin/python3 exists but is a stub that pops up an install
  # dialog instead of running Python — find_python skips it.
  if ! BASE_PY="$(find_python "$WANT_TK")"; then
    log_err "no Python 3.12 or newer found — ztrClient.py needs it (the python3 Apple ships is older)."
    log_warn "install one with Homebrew ('brew install python@3.13') or from python.org, then re-run."
    exit 1
  fi
  log_ok "using $("$BASE_PY" --version 2>&1) ($BASE_PY)."
  log_info "creating ztr's venv at $VENV_DIR ..."
  mkdir -p "$(dirname "$VENV_DIR")"
  # --copies, not the default symlink-to-system-python3 — keeps the venv's
  # interpreter a real file of its own, so nothing done to it (permissions,
  # for instance) reaches the shared system python3.
  if ! "$BASE_PY" -m venv --copies "$VENV_DIR"; then
    log_err "couldn't create the venv — check that your Python install includes the venv module."
    exit 1
  fi
  log_ok "venv created."
fi

if "$VENV_PY" -c "import Crypto" >/dev/null 2>&1; then
  log_ok "pycryptodome already installed in the venv."
else
  log_info "installing pycryptodome into the venv ..."
  "$VENV_PY" -m pip install --quiet --upgrade pip pycryptodome
  log_ok "pycryptodome installed."
fi

# Only needed for the dashboard's live traffic panel — best-effort, since
# that panel is optional and everything else works fine without it.
if [[ "$WITH_DASHBOARD" -eq 1 ]]; then
  if "$VENV_PY" -c "import scapy" >/dev/null 2>&1; then
    log_ok "scapy already installed in the venv."
    SCAPY_READY=1
  elif "$VENV_PY" -m pip install --quiet scapy; then
    log_ok "scapy installed."
    SCAPY_READY=1
  else
    log_warn "couldn't install scapy — the dashboard's live traffic panel will stay off, everything else still works."
    SCAPY_READY=0
  fi

  # Live capture on macOS reads from /dev/bpf*, which only root can open by
  # default. There's no per-binary capability to grant here (Linux's setcap),
  # and widening access to every BPF device is a system-wide change this
  # installer doesn't make for you — so it only tells you where things stand.
  if [[ "$SCAPY_READY" -eq 1 ]]; then
    if [[ -r /dev/bpf0 ]]; then
      log_ok "this account can already read /dev/bpf* — live traffic capture will work."
    else
      log_warn "live traffic capture needs read access to /dev/bpf*, which this account doesn't have. Either"
      log_warn "install a BPF-permission helper such as Wireshark's ChmodBPF, or leave the live traffic panel off;"
      log_warn "everything else on the dashboard works without it."
    fi
  fi
fi

# Only needed by ztr_requests/server.py, to sniff/decode image responses
# and pull EXIF metadata out of them — everything else in it works
# without Pillow, but the response panel would break on any image body.
if [[ "$WITH_REQUESTS" -eq 1 ]]; then
  if "$VENV_PY" -c "import PIL" >/dev/null 2>&1; then
    log_ok "Pillow already installed in the venv."
  elif "$VENV_PY" -m pip install --quiet Pillow; then
    log_ok "Pillow installed."
  else
    log_warn "couldn't install Pillow — ztr_requests will still start, but image responses will fail to render."
  fi

  # Only needed by ztr_requests/server.py's CSS-selector body search (Body
  # tab -> the search bar's "CSS selector" mode) -- everything else in
  # ztr_requests works without it; that one mode just reports an error if
  # it's missing.
  if "$VENV_PY" -c "import bs4" >/dev/null 2>&1; then
    log_ok "beautifulsoup4 already installed in the venv."
  elif "$VENV_PY" -m pip install --quiet beautifulsoup4; then
    log_ok "beautifulsoup4 installed."
  else
    log_warn "couldn't install beautifulsoup4 — ztr_requests will still start, but CSS-selector body search will fail."
  fi
fi

# ---------------------------------------------------------------------------
# ztrClient.py (RelayConfig) always resolves --config-file inside this
# folder — create it up front so it's there the moment you want to drop a
# .ztr config in, whether or not you're using --with-service.
mkdir -p "$SCRIPT_DIR/routes"

log_info "installing wrappers into $PREFIX ..."
mkdir -p "$PREFIX"

for name in "${WRAPPERS[@]}"; do
  chmod +x "$(wrapper_path "$name")"
  target="$PREFIX/$name"
  # Only overwrite what's already ours (a symlink to this plugins dir, or
  # nothing at all) — never clobber some unrelated file that happens to
  # share the name.
  if [[ -e "$target" || -L "$target" ]] && [[ "$(readlink "$target" 2>/dev/null)" != "$(wrapper_path "$name")" ]]; then
    log_warn "$target already exists and isn't one of ours — skipping (remove it yourself and re-run to install here)."
    continue
  fi
  ln -sf "$(wrapper_path "$name")" "$target"
  log_ok "$name -> $target"
done

# Two independent things can each need adding to the shell rc file: PATH
# (plus the wrapper aliases, bundled with it as before) and a `ztr_venv`
# alias for activating ztr's own venv directly — useful regardless of
# whether PREFIX is already on PATH, so it's checked on its own rather
# than being skipped along with the PATH block whenever that's already
# set up (e.g. re-running the installer after an earlier install already
# added PATH, but before this alias existed).
RC_FILE="$(detect_rc_file)"
PATH_LINE="export PATH=\"$PREFIX:\$PATH\"  # added by ztrclient installer"
VENV_ALIAS_LINE="alias ztr_venv=\"source $VENV_DIR/bin/activate\"  # added by ztrclient installer"

NEED_PATH=1
case ":$PATH:" in
  *":$PREFIX:"*) NEED_PATH=0 ;;
esac

NEED_VENV_ALIAS=1
if [[ -f "$RC_FILE" ]] && grep -qxF "$VENV_ALIAS_LINE" "$RC_FILE" 2>/dev/null; then
  NEED_VENV_ALIAS=0
fi

if [[ "$NEED_PATH" -eq 0 ]] && [[ "$NEED_VENV_ALIAS" -eq 0 ]]; then
  log_ok "$PREFIX is already on your PATH, and $RC_FILE already has the ztr_venv alias."
else
  RC_PROMPT="add to $RC_FILE:"
  [[ "$NEED_PATH" -eq 1 ]] && RC_PROMPT="$RC_PROMPT PATH + aliases for ztr_ssh/ztr_forward/ztr_pg,"
  [[ "$NEED_VENV_ALIAS" -eq 1 ]] && RC_PROMPT="$RC_PROMPT a 'ztr_venv' alias to activate ztr's venv directly,"
  RC_PROMPT="${RC_PROMPT%,}?"

  ADD_TO_RC=0
  if [[ -t 0 ]]; then
    read -r -p "$RC_PROMPT [y/N]: " ADD_TO_RC_ANSWER
    case "$ADD_TO_RC_ANSWER" in
      [yY]*) ADD_TO_RC=1 ;;
    esac
  fi

  if [[ "$ADD_TO_RC" -eq 1 ]]; then
    if [[ "$NEED_PATH" -eq 1 ]]; then
      if grep -qxF "$PATH_LINE" "$RC_FILE" 2>/dev/null; then
        log_ok "$RC_FILE already has this PATH export."
      else
        { echo ""; echo "$PATH_LINE"; } >> "$RC_FILE"
      fi
      for name in "${WRAPPERS[@]}"; do
        alias_line="alias $name=\"$(wrapper_path "$name")\"  # added by ztrclient installer"
        if ! grep -qxF "$alias_line" "$RC_FILE" 2>/dev/null; then
          echo "$alias_line" >> "$RC_FILE"
        fi
      done
    fi
    if [[ "$NEED_VENV_ALIAS" -eq 1 ]]; then
      { echo ""; echo "$VENV_ALIAS_LINE"; } >> "$RC_FILE"
    fi
    log_ok "updated $RC_FILE — open a new shell (or run: source $RC_FILE) to pick it up."
  else
    log_warn "declined — add this to your shell rc file yourself if you want it:"
    if [[ "$NEED_PATH" -eq 1 ]]; then
      echo "${C_DIM}    $PATH_LINE${C_RESET}"
      for name in "${WRAPPERS[@]}"; do
        echo "${C_DIM}    alias $name=\"$(wrapper_path "$name")\"${C_RESET}"
      done
    fi
    [[ "$NEED_VENV_ALIAS" -eq 1 ]] && echo "${C_DIM}    $VENV_ALIAS_LINE${C_RESET}"
  fi
fi

# ---------------------------------------------------------------------------
# Ferry and ZTR Proxy: check what the window needs, then put an app in
# ~/Applications. Nothing is installed for you here (Tk comes from Homebrew or
# python.org, not pip) — a missing piece is just named, with the command.
tk_hint() {
  log_warn "The Python this installer set up has no Tk 8.6 or newer, which the window needs. With Homebrew:"
  log_warn "    brew install python-tk@$("$VENV_PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  log_warn "(or install Python from python.org, which includes Tk, remove $VENV_DIR and re-run)."
}

# macOS keeps apps out of Downloads, Desktop and Documents unless you allow it per app, so an
# app that opens files from there can be refused without a word. Say so up front.
if [[ "$WITH_FERRY" -eq 1 || "$WITH_PROXY" -eq 1 ]]; then
  case "$SCRIPT_DIR" in
    "$HOME/Downloads"/*|"$HOME/Desktop"/*|"$HOME/Documents"/*)
      log_warn "ztrclient is in $(dirname "${SCRIPT_DIR#$HOME/}" | cut -d/ -f1) — macOS may stop apps opened from Launchpad or Spotlight from reading files there."
      log_warn "If an app won't open, move this folder somewhere else (for example ~/ztrclient) and run this installer again."
      ;;
  esac
fi

if [[ "$WITH_FERRY" -eq 1 ]]; then
  log_info "setting up Ferry (the file manager) ..."
  if py_has_tk "$VENV_PY"; then
    log_ok "Tk found — Ferry's window will work."
  else
    tk_hint
  fi
  command -v ssh >/dev/null 2>&1 && log_ok "ssh found." || log_warn "ssh wasn't found — Ferry can't connect without it."
  if command -v rsync >/dev/null 2>&1; then
    log_ok "rsync found ($(rsync --version 2>&1 | head -n 1))."
  else
    log_warn "rsync wasn't found — Ferry still moves a few small files without it, but folders and larger files need it: brew install rsync"
  fi
  if command -v gtar >/dev/null 2>&1; then
    log_ok "GNU tar (gtar) found — small transfers will take the fast path."
  else
    log_info "no GNU tar here — Ferry will use rsync for small transfers too (slower on a slow route, otherwise the same; 'brew install gnu-tar' adds it)."
  fi
  FERRY_ICON_TMP="$(mktemp -t ztr_ferry_icon).png"
  if "$VENV_PY" "$PLUGINS_DIR/ztr_ferry.py" --write-icon "$FERRY_ICON_TMP" && mkdir -p "$APPS_DIR" \
      && make_app_bundle "$FERRY_APP" "Ferry" "net.ztrelay.ferry" "$PLUGINS_DIR/ztr_ferry" "$FERRY_ICON_TMP" ferry; then
    log_ok "Ferry added to your Applications ($FERRY_APP)."
  else
    log_warn "couldn't create Ferry.app — 'ztr_ferry' still works from a terminal."
  fi
  rm -f "$FERRY_ICON_TMP"
fi

if [[ "$WITH_PROXY" -eq 1 ]]; then
  log_info "setting up ZTR Proxy (the browser-proxy window) ..."
  if py_has_tk "$VENV_PY"; then
    log_ok "Tk found — ZTR Proxy's window will work."
  else
    tk_hint
    log_warn "(the proxy itself still runs without a window: ztr_proxy --cli --config-file NAME.ztr)"
  fi
  PROXY_ICON_TMP="$(mktemp -t ztr_proxy_icon).png"
  if "$VENV_PY" "$PLUGINS_DIR/ztr_proxy/ztr_proxy_gui.py" --write-icon "$PROXY_ICON_TMP" && mkdir -p "$APPS_DIR" \
      && make_app_bundle "$PROXY_APP" "ZTR Proxy" "net.ztrelay.proxy" "$PLUGINS_DIR/ztr_proxy/ztr_proxy" "$PROXY_ICON_TMP" proxy; then
    log_ok "ZTR Proxy added to your Applications ($PROXY_APP)."
  else
    log_warn "couldn't create ZTR Proxy.app — 'ztr_proxy' still works from a terminal."
  fi
  rm -f "$PROXY_ICON_TMP"
fi

# ---------------------------------------------------------------------------
if [[ "$WITH_LOCAL_IP" -eq 1 ]]; then
  log_info "adding $LOCAL_IP to $LO_IF as a loopback alias (needs sudo) ..."

  # A boot daemon from an earlier run with a different address would
  # re-add that one on every boot alongside the new one — drop it first.
  OLD_IP="$(daemon_alias_ip)"
  if [[ -n "$OLD_IP" && "$OLD_IP" != "$LOCAL_IP" ]]; then
    log_info "replacing the earlier address $OLD_IP with $LOCAL_IP ..."
    remove_alias_ip "$OLD_IP"
  fi

  if local_ip_present; then
    log_ok "$LO_IF already has $LOCAL_IP — nothing to do."
  else
    sudo ifconfig "$LO_IF" alias "$LOCAL_IP" 255.255.255.255
    if local_ip_present; then
      log_ok "$LO_IF now answers on $LOCAL_IP."
    else
      log_err "couldn't confirm $LOCAL_IP was added to $LO_IF — check the sudo command's output above."
    fi
  fi

  log_info "making $LOCAL_IP persist across reboot via $LOOPBACK_DAEMON_UNIT (needs sudo) ..."
  cat <<EOF | sudo tee "$LOOPBACK_DAEMON_UNIT" >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LOOPBACK_DAEMON_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/sbin/ifconfig</string>
    <string>$LO_IF</string>
    <string>alias</string>
    <string>$LOCAL_IP</string>
    <string>255.255.255.255</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF
  # launchd refuses to load a daemon plist that isn't owned by root:wheel.
  sudo chown root:wheel "$LOOPBACK_DAEMON_UNIT"
  sudo chmod 644 "$LOOPBACK_DAEMON_UNIT"
  sudo launchctl bootout "system/$LOOPBACK_DAEMON_LABEL" >/dev/null 2>&1 || true
  if sudo launchctl bootstrap system "$LOOPBACK_DAEMON_UNIT"; then
    log_ok "persisted — $LOCAL_IP will be re-added to $LO_IF automatically on every boot from now on."
  else
    log_warn "couldn't load $LOOPBACK_DAEMON_LABEL now — it will still be picked up at the next boot."
  fi
fi

# ---------------------------------------------------------------------------
# One shared route config for both services — the tunnel service and the
# dashboard point at the same route, so this is asked once regardless of
# which one (or both) you're setting up. routes/ was already created above
# (before wrappers were even installed), so there's always somewhere to put
# the file before you're asked for it — this only ever wants a bare
# filename, never a path, since ztrClient.py (RelayConfig) always resolves
# --config-file inside routes/ itself.
if [[ "$WITH_SERVICE" -eq 1 || "$WITH_DASHBOARD" -eq 1 ]]; then
  if [[ -t 0 ]]; then
    read -r -p "Filename of your .ztr route config (already placed in routes/): " ZTR_CONFIG_NAME
  else
    log_warn "no terminal to ask for the .ztr route config on — skipping that step."
  fi
  if [[ -n "$ZTR_CONFIG_NAME" ]] && [[ ! -f "$SCRIPT_DIR/routes/$ZTR_CONFIG_NAME" ]]; then
    log_err "no routes/$ZTR_CONFIG_NAME — place your downloaded .ztr file there, then re-run with --with-service/--with-dashboard."
    ZTR_CONFIG_NAME=""
  fi
fi

if [[ "$WITH_SERVICE" -eq 1 ]]; then
  log_info "setting up ztr_tunnel_lp.py as a launchd user agent ..."

  if ! command -v launchctl >/dev/null 2>&1 || ! launchd_domain >/dev/null; then
    no_launchd_help "--with-service" "$VENV_PY $SCRIPT_DIR/plugins/ztr_tunnel_lp.py --config-file <name>.ztr --local-ip $LOCAL_IP"
  elif [[ -z "$ZTR_CONFIG_NAME" ]]; then
    log_err "no route config given — skipping service setup. Re-run with --with-service once routes/<name>.ztr is in place."
  else
    if ! local_ip_present; then
      log_warn "$LOCAL_IP isn't configured on this machine yet — sessions will fail to bind until you"
      log_warn "run './installer-macos.sh --with-local-ip' (or restart the service with --local-ip 127.0.0.1)."
    fi

    write_agent_plist "$SERVICE_UNIT" "$SERVICE_LABEL" "tunnel-lp" \
      "$VENV_PY" plugins/ztr_tunnel_lp.py --config-file "$ZTR_CONFIG_NAME" --local-ip "$LOCAL_IP"
    if load_agent "$SERVICE_LABEL" "$SERVICE_UNIT"; then
      log_ok "agent installed and started: $SERVICE_LABEL"
      agent_hints "$SERVICE_LABEL" "tunnel-lp"
    else
      log_err "couldn't load $SERVICE_LABEL — see the launchctl output above."
    fi
  fi
fi

# ---------------------------------------------------------------------------
if [[ "$WITH_DASHBOARD" -eq 1 ]]; then
  log_info "setting up ztr_dashboard.py as a launchd user agent ..."

  if ! command -v launchctl >/dev/null 2>&1 || ! launchd_domain >/dev/null; then
    no_launchd_help "--with-dashboard" "$VENV_PY $SCRIPT_DIR/plugins/ztr_dashboard.py"
  else
    # Same $ZTR_CONFIG_NAME as the tunnel service above — one route config,
    # asked once, shared by both.
    DASHBOARD_ARGS=(plugins/ztr_dashboard.py)
    if [[ -n "$ZTR_CONFIG_NAME" ]]; then
      DASHBOARD_ARGS+=(--config-file "$ZTR_CONFIG_NAME")
    fi

    # The dashboard has its own runtime fallback (127.0.0.1) when the
    # loopback address isn't around, but if this invocation is actually
    # setting it up (or it's already there), tell the dashboard explicitly
    # instead of leaving it to guess — one dedicated address, shared by
    # every service.
    if [[ "$WITH_LOCAL_IP" -eq 1 ]]; then
      DASHBOARD_ARGS+=(--host "$LOCAL_IP")
    fi

    write_agent_plist "$DASHBOARD_SERVICE_UNIT" "$DASHBOARD_LABEL" "dashboard" \
      "$VENV_PY" "${DASHBOARD_ARGS[@]}"
    if load_agent "$DASHBOARD_LABEL" "$DASHBOARD_SERVICE_UNIT"; then
      log_ok "agent installed and started: $DASHBOARD_LABEL"
      agent_hints "$DASHBOARD_LABEL" "dashboard"
    else
      log_err "couldn't load $DASHBOARD_LABEL — see the launchctl output above."
    fi
  fi
fi

# ---------------------------------------------------------------------------
if [[ "$WITH_REQUESTS" -eq 1 ]]; then
  log_info "setting up ztr_requests as a launchd user agent ..."

  if ! command -v launchctl >/dev/null 2>&1 || ! launchd_domain >/dev/null; then
    no_launchd_help "--with-requests" "$VENV_PY $SCRIPT_DIR/plugins/ztr_requests/server.py"
  else
    # No .ztr config prompt here, unlike --with-service/--with-dashboard —
    # ztr_requests picks a route per request from whatever's already in
    # routes/, via its own UI, rather than being bound to one config at
    # startup.
    REQUESTS_ARGS=(plugins/ztr_requests/server.py)

    # Same reasoning as the dashboard: its own runtime fallback
    # (127.0.0.1) covers a machine with no loopback alias, but tell it
    # explicitly when this invocation is actually setting one up (or it's
    # already there) instead of leaving it to guess.
    if [[ "$WITH_LOCAL_IP" -eq 1 ]]; then
      REQUESTS_ARGS+=(--host "$LOCAL_IP")
    fi

    write_agent_plist "$REQUESTS_SERVICE_UNIT" "$REQUESTS_LABEL" "requests" \
      "$VENV_PY" "${REQUESTS_ARGS[@]}"
    if load_agent "$REQUESTS_LABEL" "$REQUESTS_SERVICE_UNIT"; then
      log_ok "agent installed and started: $REQUESTS_LABEL"
      agent_hints "$REQUESTS_LABEL" "requests"
    else
      log_err "couldn't load $REQUESTS_LABEL — see the launchctl output above."
    fi
  fi
fi

echo
log_ok "done. Try: ztr_ssh --rh \"example._ztr\" --rp 22"
if [[ "$WITH_FERRY" -eq 1 ]]; then
  log_ok "and for the file manager: ztr_ferry   (or open Ferry from your Applications)"
fi
if [[ "$WITH_PROXY" -eq 1 ]]; then
  log_ok "and for the browser proxy: ztr_proxy   (or open ZTR Proxy from your Applications)"
fi
log_ok "and to run commands on several servers at once: ztr_fleet   (ztr_fleet --gui opens its window)"
