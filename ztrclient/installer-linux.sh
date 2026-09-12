#!/usr/bin/env bash
# Linux installer for the ZTRelay plugin wrappers (ztr_ssh, ztr_forward,
# ztr_pg) so they run from anywhere, without a manual shell alias per
# docs/ztrclient's "Alias it" sections. Does NOT touch the platform or
# ztrClient.py itself — this is scoped to plugins/ only (which is also
# where ztr_tunnel_lp.py and ztr_dashboard.py live). Linux/systemd only.
#
#   ./installer-linux.sh                       install wrappers into ~/.local/bin
#   ./installer-linux.sh --prefix DIR          install into DIR instead
#   ./installer-linux.sh --venv-dir DIR        put ztr's own Python venv at DIR instead of ~/.local/share/ztr/venv
#   ./installer-linux.sh --with-service        also set up ztr_tunnel_lp.py as a systemd --user service
#   ./installer-linux.sh --with-dashboard      also set up ztr_dashboard.py as a systemd --user service
#   ./installer-linux.sh --with-local-ip       also set up a dedicated dummy interface for tunneled sessions
#   ./installer-linux.sh --local-ip IP         use IP instead of the default 10.10.15.10
#   ./installer-linux.sh --uninstall           remove the installed wrappers (services, venv, and dummy interface, if present)
#
# Run with no flags in an actual terminal and it just asks: whether to set
# up each service, and (if either one, or if --with-local-ip was passed)
# what IP to use. --with-service/--with-dashboard/--with-local-ip/--local-ip
# above are for skipping those prompts — non-interactive runs (CI,
# provisioning scripts, piped input) skip them automatically and just take
# the flags/defaults given.
#
# What it actually does:
#   1. Makes plugins/{ztr_ssh,ztr_forward,ztr_pg} executable — a zip
#      download doesn't reliably preserve the executable bit, so this
#      isn't just belt-and-suspenders.
#   2. Checks that python3 exists, then creates a dedicated venv for ztr
#      (default ~/.local/share/ztr/venv) if one isn't already there, and
#      installs pycryptodome into it — ztr_tunnel_lp.py imports RelayClient
#      from ztrClient.py, which needs it. Keeping this in its own venv
#      instead of --user/system site-packages means it can't clash with
#      whatever else is installed on your system python3. Both systemd
#      services (--with-service, --with-dashboard) run using this venv's
#      interpreter. With --with-dashboard, also offers to install scapy
#      into it — only needed for the dashboard's live traffic panel.
#   3. Symlinks the three wrappers into --prefix (default ~/.local/bin),
#      so `ztr_ssh`/`ztr_forward`/`ztr_pg` work from any shell, not just
#      one with a hand-edited rc file. Re-running just refreshes the links.
#   4. With --with-local-ip: creates ztr_i0, a real dummy interface (`ip
#      link add ztr_i0 type dummy`), and binds --local-ip (default
#      10.10.15.10) to it, so ztr_tunnel_lp.py's per-session listeners (and
#      the dashboard, if you set it up) have a dedicated interface to bind
#      to instead of the generic 127.0.0.1 — needs sudo, requires you to
#      run this yourself. Also installs a system-level systemd unit
#      (ztr-dummy-if.service) that recreates the interface on every boot,
#      so this survives a reboot without you having to re-run anything.
#   5. With --with-service: installs ztr_tunnel_lp.py as a systemd --user
#      service, prompting for your .ztr config path.
#   6. With --with-dashboard: installs ztr_dashboard.py as a systemd --user
#      service the same way — reuses the .ztr config from --with-service
#      above if you set both up together, otherwise prompts for its own
#      (or none, if you just want the tunnel/error panels).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGINS_DIR="$SCRIPT_DIR/plugins"
WRAPPERS=(ztr_ssh ztr_forward ztr_pg)

PREFIX="${PREFIX:-$HOME/.local/bin}"
VENV_DIR="${VENV_DIR:-$HOME/.local/share/ztr/venv}"
LOCAL_IP="${LOCAL_IP:-10.10.15.10}"
LOCAL_IP_SET_BY_USER=0
WITH_SERVICE=0
WITH_SERVICE_SET_BY_USER=0
WITH_DASHBOARD=0
WITH_DASHBOARD_SET_BY_USER=0
WITH_LOCAL_IP=0
UNINSTALL=0

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

usage() {
  sed -n '2,53p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

SERVICE_UNIT="$HOME/.config/systemd/user/ztr-tunnel-lp.service"
DASHBOARD_SERVICE_UNIT="$HOME/.config/systemd/user/ztr-dashboard.service"
IFACE_NAME="ztr_i0"
DUMMY_IF_UNIT="/etc/systemd/system/ztr-dummy-if.service"

# Ask up front rather than requiring you to already know the flag exists —
# only when you didn't already say one way or the other with --with-service,
# and only when actually running interactively (skip in scripts/CI, and
# skip entirely for --uninstall, which doesn't need this).
if [[ "$WITH_SERVICE_SET_BY_USER" -eq 0 && "$UNINSTALL" -eq 0 && -t 0 ]]; then
  read -r -p "Set up ztr_tunnel_lp.py as a persistent systemd --user service? [y/N]: " WITH_SERVICE_ANSWER
  case "$WITH_SERVICE_ANSWER" in
    [yY]*) WITH_SERVICE=1 ;;
  esac
fi

# Same idea, asked separately — the dashboard doesn't need the tunnel
# service (or vice versa), so answering one shouldn't silently decide the
# other.
if [[ "$WITH_DASHBOARD_SET_BY_USER" -eq 0 && "$UNINSTALL" -eq 0 && -t 0 ]]; then
  read -r -p "Set up ztr_dashboard.py as a persistent systemd --user service? [y/N]: " WITH_DASHBOARD_ANSWER
  case "$WITH_DASHBOARD_ANSWER" in
    [yY]*) WITH_DASHBOARD=1 ;;
  esac
fi

# The service is useless without somewhere to bind its per-session
# listeners — without the dummy interface, every session fails to start
# the moment the service is actually up. So --with-service (flag or the
# prompt above) implies --with-local-ip, not just the "what IP" prompt
# below — this is what actually creates the interface later on.
if [[ "$WITH_SERVICE" -eq 1 ]]; then
  WITH_LOCAL_IP=1
fi

# Ask rather than silently defaulting — this address matters (it's what
# ztr_tunnel_lp.py binds to and every wrapper connects through), so
# anyone with a reason to pick their own subnet should get the chance
# before it's baked into a systemd unit. Only asks if --local-ip wasn't
# already given, and only when actually running interactively (skip in
# scripts/CI, where stdin isn't a terminal — reading from it there would
# either hang or consume unrelated piped input).
if [[ "$LOCAL_IP_SET_BY_USER" -eq 0 && ( "$WITH_LOCAL_IP" -eq 1 || "$WITH_SERVICE" -eq 1 ) && -t 0 ]]; then
  read -r -p "Dummy IP for tunneled sessions to bind to [$LOCAL_IP]: " LOCAL_IP_INPUT
  if [[ -n "$LOCAL_IP_INPUT" ]]; then
    LOCAL_IP="$LOCAL_IP_INPUT"
  fi
fi

# ---------------------------------------------------------------------------
# Dummy-interface helpers — a real interface ($IFACE_NAME), not a loopback
# alias, so tunneled traffic shows up as its own thing (its own line in
# `ip addr`, its own interface in netstat/ss) instead of piggybacking on lo.
# Made persistent by $DUMMY_IF_UNIT, a system-level (not --user) systemd
# unit that recreates it at boot — see the --with-local-ip block below.

local_ip_present() {
  ip addr show dev "$IFACE_NAME" 2>/dev/null | grep -q " ${LOCAL_IP}/"
}

remove_local_ip() {
  sudo ip link delete "$IFACE_NAME" >/dev/null 2>&1 || true
}

# bash -> ~/.bashrc (what most terminal emulators source for an
# interactive non-login shell); anything else -> ~/.zshrc or ~/.profile.
# Defined up here (not just near where it's used) so uninstall() — which
# runs and exits before the rest of the script — can use it too.
detect_rc_file() {
  case "$(basename "${SHELL:-}")" in
    zsh) echo "$HOME/.zshrc" ;;
    bash) echo "$HOME/.bashrc" ;;
    *) echo "$HOME/.profile" ;;
  esac
}

# ---------------------------------------------------------------------------
uninstall() {
  log_info "removing wrappers from $PREFIX ..."
  local removed=0
  for name in "${WRAPPERS[@]}"; do
    local link="$PREFIX/$name"
    # Only remove it if it's actually our symlink — never clobber some
    # unrelated file that happens to share the name.
    if [[ -L "$link" ]] && [[ "$(readlink "$link")" == "$PLUGINS_DIR/$name" ]]; then
      rm -f "$link"
      removed=1
    fi
  done
  [[ "$removed" -eq 1 ]] && log_ok "wrappers removed." || log_warn "no installed wrappers found in $PREFIX."

  if [[ -f "$SERVICE_UNIT" ]]; then
    log_info "stopping and removing the ztr-tunnel-lp systemd service ..."
    systemctl --user disable --now ztr-tunnel-lp.service >/dev/null 2>&1 || true
    rm -f "$SERVICE_UNIT"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    log_ok "service removed."
  fi

  if [[ -f "$DASHBOARD_SERVICE_UNIT" ]]; then
    log_info "stopping and removing the ztr-dashboard systemd service ..."
    systemctl --user disable --now ztr-dashboard.service >/dev/null 2>&1 || true
    rm -f "$DASHBOARD_SERVICE_UNIT"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    log_ok "service removed."
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
    tmp_rc="$(mktemp)"
    grep -vxF "$path_line" "$rc_file" > "$tmp_rc"
    for name in "${WRAPPERS[@]}"; do
      local alias_line="alias $name=\"$PLUGINS_DIR/$name\"  # added by ztrclient installer"
      grep -vxF "$alias_line" "$tmp_rc" > "$tmp_rc.next" && mv "$tmp_rc.next" "$tmp_rc"
    done
    mv "$tmp_rc" "$rc_file"
    log_ok "removed from $rc_file."
  fi

  if [[ -f "$DUMMY_IF_UNIT" ]]; then
    log_info "removing the $IFACE_NAME persistence unit (needs sudo) ..."
    sudo systemctl disable --now "$(basename "$DUMMY_IF_UNIT")" >/dev/null 2>&1 || true
    sudo rm -f "$DUMMY_IF_UNIT"
    sudo systemctl daemon-reload >/dev/null 2>&1 || true
    log_ok "persistence unit removed."
  fi

  if local_ip_present || ip link show "$IFACE_NAME" >/dev/null 2>&1; then
    log_info "removing the $IFACE_NAME interface (needs sudo) ..."
    if remove_local_ip && ! ip link show "$IFACE_NAME" >/dev/null 2>&1; then
      log_ok "$IFACE_NAME removed."
    else
      log_warn "couldn't confirm $IFACE_NAME was removed — remove it yourself if it's still there."
    fi
  fi
  exit 0
}
[[ "$UNINSTALL" -eq 1 ]] && uninstall

# ---------------------------------------------------------------------------
# Run as yourself, not root — a very easy mistake on a Pi/VPS where sudo is
# passwordless or habitual. Under `sudo ./installer-linux.sh`, $HOME is
# root's, so the venv and wrapper symlinks land in the wrong place, and (if
# --with-service is used) `systemctl --user` targets root's session bus,
# which usually isn't running — that's the
# "Failed to connect to user scope bus ... XDG_RUNTIME_DIR not defined"
# error. The few commands that do need privilege (--with-local-ip's dummy
# interface) already call sudo themselves, just for that piece.
if [[ "$(id -u)" -eq 0 ]] && [[ -z "${ZTR_ALLOW_ROOT:-}" ]]; then
  log_err "running as root (or via sudo) — re-run this as your normal user instead, without sudo."
  log_warn "it'll prompt for your password itself on the one part that actually needs it"
  log_warn "(--with-local-ip's dummy network interface). If you really do mean to install this"
  log_warn "for root specifically, set ZTR_ALLOW_ROOT=1 to skip this check."
  exit 1
fi

log_info "checking prerequisites ..."

if ! command -v python3 >/dev/null 2>&1; then
  log_err "python3 not found — required by every plugin wrapper and by ztr_tunnel_lp.py itself."
  exit 1
fi
log_ok "python3 found ($(command -v python3))."

VENV_PY="$VENV_DIR/bin/python3"
if [[ -x "$VENV_PY" ]]; then
  log_ok "ztr venv already exists at $VENV_DIR."
else
  log_info "creating ztr's venv at $VENV_DIR ..."
  mkdir -p "$(dirname "$VENV_DIR")"
  # --copies, not the default symlink-to-system-python3 — matters for
  # --with-dashboard's setcap below: capabilities follow the real file, so
  # setcap-ing a symlink would actually grant raw-socket capture to the
  # shared system python3, not just this venv's own interpreter.
  if ! python3 -m venv --copies "$VENV_DIR"; then
    log_err "couldn't create the venv — on Debian/Ubuntu you likely need: sudo apt install python3-venv"
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

  # Actually make live capture work, not just possible — a systemd --user
  # service has no raw-socket privileges by default, and running the whole
  # dashboard as root for one panel is more than this needs. cap_net_raw
  # grants just that, to this venv's interpreter specifically (same
  # mechanism dumpcap/Wireshark use to avoid running fully as root).
  if [[ "$SCAPY_READY" -eq 1 ]]; then
    if ! command -v setcap >/dev/null 2>&1; then
      log_warn "setcap not found (Debian/Ubuntu: sudo apt install libcap2-bin) — live traffic capture needs"
      log_warn "either that or running ztr-dashboard.service as root; everything else still works without it."
    elif sudo setcap cap_net_raw,cap_net_admin=eip "$VENV_PY"; then
      log_ok "granted $VENV_PY raw-socket capture capability — live traffic will work without running as root."
    else
      log_warn "couldn't grant capture capability to $VENV_PY — live traffic capture will stay off."
    fi
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
  chmod +x "$PLUGINS_DIR/$name"
  target="$PREFIX/$name"
  # Only overwrite what's already ours (a symlink to this plugins dir, or
  # nothing at all) — never clobber some unrelated file that happens to
  # share the name.
  if [[ -e "$target" || -L "$target" ]] && [[ "$(readlink "$target" 2>/dev/null)" != "$PLUGINS_DIR/$name" ]]; then
    log_warn "$target already exists and isn't one of ours — skipping (remove it yourself and re-run to install here)."
    continue
  fi
  ln -sf "$PLUGINS_DIR/$name" "$target"
  log_ok "$name -> $target"
done

case ":$PATH:" in
  *":$PREFIX:"*)
    log_ok "$PREFIX is already on your PATH."
    ;;
  *)
    RC_FILE="$(detect_rc_file)"
    PATH_LINE="export PATH=\"$PREFIX:\$PATH\"  # added by ztrclient installer"
    ADD_TO_RC=0
    if [[ -t 0 ]]; then
      read -r -p "$PREFIX isn't on your PATH yet — add PATH + shell aliases for ztr_ssh/ztr_forward/ztr_pg to $RC_FILE? [y/N]: " ADD_TO_RC_ANSWER
      case "$ADD_TO_RC_ANSWER" in
        [yY]*) ADD_TO_RC=1 ;;
      esac
    fi
    if [[ "$ADD_TO_RC" -eq 1 ]]; then
      if grep -qxF "$PATH_LINE" "$RC_FILE" 2>/dev/null; then
        log_ok "$RC_FILE already has this PATH export."
      else
        { echo ""; echo "$PATH_LINE"; } >> "$RC_FILE"
      fi
      for name in "${WRAPPERS[@]}"; do
        alias_line="alias $name=\"$PLUGINS_DIR/$name\"  # added by ztrclient installer"
        if ! grep -qxF "$alias_line" "$RC_FILE" 2>/dev/null; then
          echo "$alias_line" >> "$RC_FILE"
        fi
      done
      log_ok "added PATH + aliases to $RC_FILE — open a new shell (or run: source $RC_FILE) to pick it up."
    else
      log_warn "$PREFIX is not on your PATH yet — add this to your shell rc file:"
      echo "${C_DIM}    $PATH_LINE${C_RESET}"
      for name in "${WRAPPERS[@]}"; do
        echo "${C_DIM}    alias $name=\"$PLUGINS_DIR/$name\"${C_RESET}"
      done
    fi
    ;;
esac

# ---------------------------------------------------------------------------
if [[ "$WITH_LOCAL_IP" -eq 1 ]]; then
  log_info "setting up $IFACE_NAME as a dummy interface bound to $LOCAL_IP (needs sudo) ..."

  if ip link show "$IFACE_NAME" >/dev/null 2>&1 && ! local_ip_present; then
    log_info "$IFACE_NAME already exists with a different address — recreating it for $LOCAL_IP ..."
    sudo ip link delete "$IFACE_NAME" >/dev/null 2>&1 || true
  fi

  if local_ip_present; then
    log_ok "$IFACE_NAME already has $LOCAL_IP — nothing to do."
  else
    sudo ip link add "$IFACE_NAME" type dummy
    sudo ip addr add "$LOCAL_IP/32" dev "$IFACE_NAME"
    sudo ip link set "$IFACE_NAME" up
    if local_ip_present; then
      log_ok "$IFACE_NAME up with $LOCAL_IP."
    else
      log_err "couldn't confirm $IFACE_NAME was configured — check the sudo commands' output above."
    fi
  fi

  log_info "making $IFACE_NAME persist across reboot via $DUMMY_IF_UNIT (needs sudo) ..."
  cat <<EOF | sudo tee "$DUMMY_IF_UNIT" >/dev/null
[Unit]
Description=ZTRelay dummy network interface ($IFACE_NAME)
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip link add $IFACE_NAME type dummy
ExecStart=/sbin/ip addr add $LOCAL_IP/32 dev $IFACE_NAME
ExecStart=/sbin/ip link set $IFACE_NAME up
ExecStop=/sbin/ip link delete $IFACE_NAME

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable "$(basename "$DUMMY_IF_UNIT")" >/dev/null 2>&1
  log_ok "persisted — $IFACE_NAME will be recreated automatically on every boot from now on."
fi

# ---------------------------------------------------------------------------
if [[ "$WITH_SERVICE" -eq 1 ]]; then
  log_info "setting up ztr_tunnel_lp.py as a systemd --user service ..."

  if ! command -v systemctl >/dev/null 2>&1; then
    log_err "systemctl not found — this installer is Linux/systemd-specific."
    log_warn "run it standalone instead: $VENV_PY $SCRIPT_DIR/plugins/ztr_tunnel_lp.py --config-file route.ztr"
  elif [[ -z "${XDG_RUNTIME_DIR:-}" ]] || ! systemctl --user show-environment >/dev/null 2>&1; then
    # "Failed to connect to user scope bus via local transport ..." — no
    # systemd --user session/D-Bus reachable for this account. Common when
    # you su/sudo'd into this user instead of logging in as them directly,
    # or you're in a container/WSL setup where systemd --user never started
    # for anyone. Caught here, before asking for a config path, rather than
    # letting the raw dbus error below kill the script under `set -e`.
    log_err "no systemd --user session available for this account (XDG_RUNTIME_DIR unset, or its D-Bus isn't reachable)."
    log_warn "if you reached this shell via su/sudo into this user: log in directly as them instead (SSH or"
    log_warn "console) and re-run. If you're already logged in directly: try 'loginctl enable-linger \$USER',"
    log_warn "then log out and back in. If systemd doesn't run here at all (containers, WSL without systemd"
    log_warn "enabled), --with-service can't work — run the tunnel yourself instead, in the foreground:"
    log_warn "    $VENV_PY $SCRIPT_DIR/plugins/ztr_tunnel_lp.py --config-file <name>.ztr --local-ip $LOCAL_IP"
  else
    read -r -p "Path to your downloaded .ztr route config: " ZTR_CONFIG_SRC
    if [[ ! -f "$ZTR_CONFIG_SRC" ]]; then
      log_err "no file at $ZTR_CONFIG_SRC — skipping service setup. Re-run with --with-service once it's in place."
    else
      # ztrClient.py (RelayConfig) always resolves --config-file inside
      # routes/, next to itself — never a path you hand it directly. Copy
      # whatever you pointed at in there under its own name, so every .ztr
      # config ends up in one place regardless of where it was downloaded to.
      mkdir -p "$SCRIPT_DIR/routes"
      ZTR_CONFIG_NAME="$(basename "$ZTR_CONFIG_SRC")"
      ZTR_CONFIG_DEST="$SCRIPT_DIR/routes/$ZTR_CONFIG_NAME"
      ZTR_CONFIG_SRC_ABS="$(cd "$(dirname "$ZTR_CONFIG_SRC")" && pwd)/$ZTR_CONFIG_NAME"
      if [[ "$ZTR_CONFIG_SRC_ABS" != "$ZTR_CONFIG_DEST" ]]; then
        cp "$ZTR_CONFIG_SRC" "$ZTR_CONFIG_DEST"
        log_ok "copied to $ZTR_CONFIG_DEST"
      fi

      if ! local_ip_present; then
        log_warn "$LOCAL_IP isn't configured on this machine yet — sessions will fail to bind until you"
        log_warn "run './installer-linux.sh --with-local-ip' (or restart the service with --local-ip 127.0.0.1)."
      fi

      mkdir -p "$(dirname "$SERVICE_UNIT")"
      cat > "$SERVICE_UNIT" <<EOF
[Unit]
Description=ZTRelay Tunnel local proxy
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
ExecStart=$VENV_PY plugins/ztr_tunnel_lp.py --config-file $ZTR_CONFIG_NAME --local-ip $LOCAL_IP
Restart=on-failure

[Install]
WantedBy=default.target
EOF
      systemctl --user daemon-reload
      systemctl --user enable --now ztr-tunnel-lp.service
      log_ok "service installed and started: ztr-tunnel-lp.service"
      echo "${C_DIM}    systemctl --user status ztr-tunnel-lp.service${C_RESET}"
      echo "${C_DIM}    journalctl --user -u ztr-tunnel-lp.service -f${C_RESET}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
if [[ "$WITH_DASHBOARD" -eq 1 ]]; then
  log_info "setting up ztr_dashboard.py as a systemd --user service ..."

  if ! command -v systemctl >/dev/null 2>&1; then
    log_err "systemctl not found — this installer is Linux/systemd-specific."
    log_warn "run it standalone instead: $VENV_PY $SCRIPT_DIR/plugins/ztr_dashboard.py --config-file route.ztr"
  elif [[ -z "${XDG_RUNTIME_DIR:-}" ]] || ! systemctl --user show-environment >/dev/null 2>&1; then
    # Same "no systemd --user session" case as --with-service above.
    log_err "no systemd --user session available for this account (XDG_RUNTIME_DIR unset, or its D-Bus isn't reachable)."
    log_warn "if you reached this shell via su/sudo into this user: log in directly as them instead (SSH or"
    log_warn "console) and re-run. If you're already logged in directly: try 'loginctl enable-linger \$USER',"
    log_warn "then log out and back in. If systemd doesn't run here at all (containers, WSL without systemd"
    log_warn "enabled), --with-dashboard can't work — run it yourself instead, in the foreground:"
    log_warn "    $VENV_PY $SCRIPT_DIR/plugins/ztr_dashboard.py"
  else
    # The tunnel service's config, if this run also set one up, IS this
    # route's config — reuse it silently rather than asking again for the
    # same path. Only prompt when there's genuinely nothing to reuse.
    if [[ -n "${ZTR_CONFIG_NAME:-}" ]]; then
      ZTR_DASHBOARD_CONFIG_SRC="$ZTR_CONFIG_NAME"
      log_info "using the same route config as the tunnel service: $ZTR_CONFIG_NAME"
    else
      read -r -p "Path to a .ztr route config for the dashboard to diagram (blank for none): " ZTR_DASHBOARD_CONFIG_SRC
    fi

    DASHBOARD_EXEC="plugins/ztr_dashboard.py"
    if [[ -n "$ZTR_DASHBOARD_CONFIG_SRC" ]]; then
      # Same as --with-service above: whatever it points at ends up as its
      # own file directly inside routes/, since that's the only place
      # ztrClient.py (RelayConfig) will ever look for it.
      if [[ -f "$ZTR_DASHBOARD_CONFIG_SRC" ]]; then
        mkdir -p "$SCRIPT_DIR/routes"
        ZTR_DASHBOARD_CONFIG_NAME="$(basename "$ZTR_DASHBOARD_CONFIG_SRC")"
        ZTR_DASHBOARD_CONFIG_DEST="$SCRIPT_DIR/routes/$ZTR_DASHBOARD_CONFIG_NAME"
        ZTR_DASHBOARD_CONFIG_SRC_ABS="$(cd "$(dirname "$ZTR_DASHBOARD_CONFIG_SRC")" && pwd)/$ZTR_DASHBOARD_CONFIG_NAME"
        if [[ "$ZTR_DASHBOARD_CONFIG_SRC_ABS" != "$ZTR_DASHBOARD_CONFIG_DEST" ]]; then
          cp "$ZTR_DASHBOARD_CONFIG_SRC" "$ZTR_DASHBOARD_CONFIG_DEST"
          log_ok "copied to $ZTR_DASHBOARD_CONFIG_DEST"
        fi
        DASHBOARD_EXEC="$DASHBOARD_EXEC --config-file $ZTR_DASHBOARD_CONFIG_NAME"
      elif [[ -f "$SCRIPT_DIR/routes/$ZTR_DASHBOARD_CONFIG_SRC" ]]; then
        # Already just a name sitting in routes/ (e.g. reused from
        # --with-service above, which already copied it there).
        DASHBOARD_EXEC="$DASHBOARD_EXEC --config-file $ZTR_DASHBOARD_CONFIG_SRC"
      else
        log_warn "no file at $ZTR_DASHBOARD_CONFIG_SRC — starting the dashboard without a config (tunnel/error panels only)."
      fi
    fi

    # The dashboard has its own runtime fallback (127.0.0.1) when the dummy
    # IP isn't around, but if this invocation is actually setting it up
    # (or it's already there), tell the dashboard explicitly instead of
    # leaving it to guess — one dedicated address, shared by both services.
    if [[ "$WITH_LOCAL_IP" -eq 1 ]]; then
      DASHBOARD_EXEC="$DASHBOARD_EXEC --host $LOCAL_IP"
    fi

    mkdir -p "$(dirname "$DASHBOARD_SERVICE_UNIT")"
    cat > "$DASHBOARD_SERVICE_UNIT" <<EOF
[Unit]
Description=ZTRelay client dashboard
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
ExecStart=$VENV_PY $DASHBOARD_EXEC
Restart=on-failure

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now ztr-dashboard.service
    log_ok "service installed and started: ztr-dashboard.service"
    echo "${C_DIM}    systemctl --user status ztr-dashboard.service${C_RESET}"
    echo "${C_DIM}    journalctl --user -u ztr-dashboard.service -f${C_RESET}"
  fi
fi

echo
log_ok "done. Try: ztr_ssh --rh \"example._ztr\" --rp 22"
