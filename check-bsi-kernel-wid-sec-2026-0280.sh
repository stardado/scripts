
#!/usr/bin/env sh
set -e

have_cmd() { command -v "$1" >/dev/null 2>&1; }

hr() { printf "%s\n" "------------------------------------------------------------"; }

OS_ID="unknown"; OS_VER="unknown"; OS_NAME="unknown"; OS_CODENAME=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_VER="${VERSION_ID:-unknown}"
  OS_NAME="${PRETTY_NAME:-unknown}"
  OS_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
fi

KREL="$(uname -r 2>/dev/null || echo unknown)"
HOST="$(hostname 2>/dev/null || echo unknown)"

# Find a kernel config source
CFG_SRC=""
if [ -r /proc/config.gz ] && have_cmd zgrep; then
  CFG_SRC="/proc/config.gz"
elif [ -r "/boot/config-$KREL" ]; then
  CFG_SRC="/boot/config-$KREL"
elif [ -r /boot/config ]; then
  CFG_SRC="/boot/config"
fi

cfg_get() {
  # prints: y|m|n|unknown
  key="$1"
  [ -n "$CFG_SRC" ] || { echo "unknown"; return; }

  if [ "$CFG_SRC" = "/proc/config.gz" ]; then
    line="$(zgrep -E "^${key}=" "$CFG_SRC" 2>/dev/null | tail -n 1 || true)"
  else
    line="$(grep -E "^${key}=" "$CFG_SRC" 2>/dev/null | tail -n 1 || true)"
  fi

  case "$line" in
    *"=y") echo "y" ;;
    *"=m") echo "m" ;;
    *"=n") echo "n" ;;
    *) echo "unknown" ;;
  esac
}

lsmod_has() {
  # $1 module name (may contain -); compare with lsmod output (usually _)
  mod="$1"
  mod_norm="$(printf "%s" "$mod" | tr '-' '_')"
  have_cmd lsmod || return 1
  lsmod | awk 'NR>1{print $1}' | grep -qx "$mod_norm"
}

mod_present() {
  # tries a list of module names, echoes the first that exists, else empty
  # requires modinfo
  have_cmd modinfo || { echo ""; return; }
  for m in "$@"; do
    if modinfo "$m" >/dev/null 2>&1; then
      echo "$m"
      return
    fi
  done
  echo ""
}

check_item() {
  cve="$1"
  cfg="$2"
  mods="$3"     # space-separated list
  desc="$4"

  cfg_state="$(cfg_get "$cfg")"
  # shellcheck disable=SC2086
  present="$(mod_present $mods)"
  loaded="no"
  active="no"

  if [ "$cfg_state" = "y" ]; then
    active="yes (built-in)"
  elif [ "$cfg_state" = "m" ]; then
    active="yes (module-capable)"
  fi

  if [ -n "$present" ]; then
    if lsmod_has "$present"; then
      loaded="yes"
      active="yes (loaded)"
    else
      loaded="no"
    fi
  fi

  printf "%s\n" "$cve  –  $desc"
  printf "  Kernel-Config: %s (%s)\n" "$cfg" "$cfg_state"
  if [ -n "$present" ]; then
    printf "  Modul:         %s (vorhanden), geladen: %s\n" "$present" "$loaded"
  else
    printf "  Modul:         nicht gefunden (evtl. nicht im Kernel enthalten)\n"
  fi
  printf "  Einschätzung:  %s\n" "$active"
  printf "\n"
}

echo "Host:   $HOST"
echo "OS:     $OS_NAME (id=$OS_ID version=$OS_VER codename=${OS_CODENAME:-n/a})"
echo "Kernel: $KREL"
if [ -n "$CFG_SRC" ]; then
  echo "Config: $CFG_SRC"
else
  echo "Config: (nicht gefunden) – Config-Checks nur eingeschränkt möglich"
fi
hr

echo "CVE/Subsystem-Checks (praktische Betroffenheit = Subsystem im Kernel aktiv):"
echo

# CVE-2026-23020 – 3c59x / Vortex/Boomerang (CONFIG_VORTEX, module 3c59x)
check_item "CVE-2026-23020" "CONFIG_VORTEX" "3c59x" "3Com 3c59x (Vortex/Boomerang) Netzwerk-Treiber"

# CVE-2026-23039 – DRM GUD (CONFIG_DRM_GUD, module gud)
check_item "CVE-2026-23039" "CONFIG_DRM_GUD" "gud" "DRM GUD USB-Display-Treiber"

# CVE-2026-23015 – GPIO MPSSE (CONFIG_GPIO_MPSSE, module gpio-mpsse/gpio_mpsse)
check_item "CVE-2026-23015" "CONFIG_GPIO_MPSSE" "gpio-mpsse gpio_mpsse" "FTDI MPSSE GPIO Treiber"

# CVE-2025-71180 – interrupt counter (CONFIG_INTERRUPT_CNT, module interrupt-cnt/interrupt_cnt)
check_item "CVE-2025-71180" "CONFIG_INTERRUPT_CNT" "interrupt-cnt interrupt_cnt" "Interrupt Counter Driver (drivers/counter/interrupt-cnt)"

# CVE-2025-71182 – CAN J1939 (CONFIG_CAN_J1939, module can-j1939/can_j1939)
check_item "CVE-2025-71182" "CONFIG_CAN_J1939" "can-j1939 can_j1939" "CAN J1939 Protokoll (SocketCAN)"

hr

# Reboot-needed check (best effort)
latest_vmlinuz="$(ls -1 /boot/vmlinuz-* 2>/dev/null | sort -V 2>/dev/null | tail -n 1 || true)"
if [ -n "$latest_vmlinuz" ]; then
  latest_k="$(basename "$latest_vmlinuz" | sed 's/^vmlinuz-//')"
  if [ "$latest_k" != "$KREL" ]; then
    echo "⚠️  Reboot empfohlen: In /boot liegt ein neuerer Kernel: $latest_k (aktuell: $KREL)"
  else
    echo "✅ Kein Reboot-Hinweis aus /boot/vmlinuz-*: laufender Kernel scheint aktuell installiert zu sein."
  fi
else
  echo "Hinweis: Konnte /boot/vmlinuz-* nicht auswerten (evtl. Container/anderes Layout)."
fi

if [ -f /var/run/reboot-required ]; then
  echo "⚠️  /var/run/reboot-required vorhanden: System signalisiert Neustartbedarf."
fi

hr
echo "Kernel-Update-Check (nur Anzeige, keine Installation):"

if have_cmd apt-get; then
  echo "- Paketmanager: apt"
  # nutzt vorhandene Paketlisten (kein apt update)
  upg="$(apt-get -s dist-upgrade 2>/dev/null | awk '
    $1=="Inst" && ($2 ~ /^linux-image/ || $2 ~ /^linux-headers/ || $2 ~ /^linux-modules/ || $2 ~ /^linux-generic/ || $2 ~ /^linux-hwe/ || $2 ~ /^linux-aws/ || $2 ~ /^linux-azure/ || $2 ~ /^linux-gcp/) {
      print "  * " $2 " -> " $3
    }' || true)"
  if [ -n "$upg" ]; then
    echo "⚠️  Mögliche Kernel-bezogene Updates gefunden:"
    echo "$upg"
    echo "   Tipp: vor dem echten Update ggf. 'apt update' laufen lassen, dann 'apt upgrade'."
  else
    echo "✅ Keine Kernel-Pakete in der Simulation gefunden (ggf. erst 'apt update' nötig)."
  fi

elif have_cmd dnf; then
  echo "- Paketmanager: dnf"
  if dnf -q check-update 'kernel*' >/dev/null 2>&1; then
    echo "✅ dnf meldet keine kernel*-Updates."
  else
    echo "⚠️  dnf: kernel*-Updates könnten verfügbar sein (check-update hat Treffer oder Fehler)."
    echo "   Tipp: 'dnf check-update kernel*' bzw. 'dnf update kernel*'"
  fi

elif have_cmd yum; then
  echo "- Paketmanager: yum"
  if yum -q check-update 'kernel*' >/dev/null 2>&1; then
    echo "✅ yum meldet keine kernel*-Updates."
  else
    echo "⚠️  yum: kernel*-Updates könnten verfügbar sein (check-update hat Treffer oder Fehler)."
  fi

elif have_cmd zypper; then
  echo "- Paketmanager: zypper"
  # list patches that are needed; kernel patches are usually in there
  patches="$(zypper -q lp -g security -g recommended 2>/dev/null | grep -i kernel || true)"
  if [ -n "$patches" ]; then
    echo "⚠️  zypper zeigt kernel-bezogene Patches:"
    echo "$patches"
  else
    echo "✅ Keine kernel-Zeilen in zypper patch-liste gefunden (ggf. 'zypper refresh' nötig)."
  fi

elif have_cmd pacman; then
  echo "- Paketmanager: pacman"
  echo "Hinweis: pacman-Checks sind ohne Sync nicht zuverlässig."
  echo "Tipp: 'pacman -Sy' und dann 'pacman -Qu | grep -E \"^linux\"'"

else
  echo "Hinweis: Kein unterstützter Paketmanager gefunden (apt/dnf/yum/zypper/pacman)."
fi

hr
echo "Fazit:"
echo "1) Wenn oben ein Subsystem als 'built-in' oder 'loaded' auftaucht: dann ist es praktisch relevant."
echo "2) Wenn Kernel-Updates angezeigt werden: einspielen."
echo "3) Wenn ein neuerer Kernel installiert ist: reboot einplanen."
