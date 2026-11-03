#!/usr/bin/env bash
#
# ============================================================================
#  bvrt-streamer :: install.sh  —  bootstrap del instalador endurecido
# ----------------------------------------------------------------------------
#  Esto NO es un `curl | bash` a ciegas. Hace, en este orden:
#    1. Comprueba que eres root y que la distro tiene lo mínimo.
#    2. Descarga el instalador endurecido a un archivo (nunca a un pipe).
#    3. Verifica su SHA256 contra un valor que TÚ confías (parámetro, variable
#       o el archivo .sha256 de la release).
#    4. Te lo muestra y te pide confirmación explícita.
#    5. Lo ejecuta.
#
#  Uso:
#    curl -fsSL -O https://raw.githubusercontent.com/TalaveraSama/bvrt-streamer/main/install.sh
#    sha256sum install.sh          # compáralo con el que publicamos en la release
#    sudo bash install.sh
#
#  Variables:
#    MS_PAYLOAD_SHA256   hash del .tar.gz del panel (OBLIGATORIO, lo calculas tú)
#    MS_PAYLOAD          ruta al .tar.gz (si no, lo busca en el directorio actual)
#    MS_INSTALLER_SHA256 hash esperado del instalador (si no, usa el .sha256)
#    MS_REF              rama/tag origen (por defecto: main)
#    MS_YES=1            no preguntar (solo si ya sabes lo que haces)
#
#  Códigos de salida: 0 ok · 1 error de entorno · 2 checksum inválido
#                     3 usuario canceló · 4 fallo del instalador
# ============================================================================
set -uo pipefail

MS_REPO="TalaveraSama/bvrt-streamer"
MS_REF="${MS_REF:-v0.1.0}"
MS_BASE="https://raw.githubusercontent.com/${MS_REPO}/${MS_REF}"

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[93m'; CYA='\033[96m'; NC='\033[0m'
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
warn() { echo -e "${YEL}[WARN]${NC} $*" >&2; }
info() { echo -e "${CYA}[INFO]${NC} $*"; }

echo
echo "=========================================================="
echo " bvrt-streamer · instalador de MidnightStreamer endurecido"
echo " origen: ${MS_REPO} @ ${MS_REF}"
echo "=========================================================="
echo

# ---------------------------------------------------------------------------
# 1 · Entorno
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "ejecuta como root:  sudo bash $0"

command -v curl >/dev/null 2>&1 || die "falta curl (apt-get install -y curl)"
command -v sha256sum >/dev/null 2>&1 || die "falta sha256sum (coreutils)"
command -v tar >/dev/null 2>&1 || die "falta tar"
command -v openssl >/dev/null 2>&1 || die "falta openssl"

if [ -r /etc/os-release ]; then
    . /etc/os-release
    info "sistema: ${PRETTY_NAME:-desconocido}"
    case "${ID:-}" in
        ubuntu|debian) : ;;
        *) warn "no es Ubuntu/Debian: el instalador solo soporta apt/yum; continúa bajo tu riesgo" ;;
    esac
fi

# Aviso si ya hay una instalación
if [ -d /home/midnightstreamer/iptv_midnight_streamer/cms ]; then
    warn "ya existe una instalación del panel en este servidor"
    warn "el instalador limpia /home/midnightstreamer/iptv_midnight_streamer (con backup de BD)"
fi

# ---------------------------------------------------------------------------
# 2 · Descargar a archivo (nunca a un pipe)
# ---------------------------------------------------------------------------
WORKDIR=$(mktemp -d /root/bvrt-install.XXXXXX) || die "no se pudo crear dir temporal"
chmod 700 "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT

INSTALLER="$WORKDIR/ms_install_offline.sh"
info "descargando instalador…"
curl -fsSL --retry 3 --max-time 120 -o "$INSTALLER" \
    "${MS_BASE}/installer/ms_install_offline.sh" \
    || die "no se pudo descargar el instalador desde ${MS_BASE}"

[ -s "$INSTALLER" ] || die "el instalador descargado está vacío"
bash -n "$INSTALLER" || die "el instalador descargado tiene errores de sintaxis (¿descarga corrupta?)"

# ---------------------------------------------------------------------------
# 3 · Verificar integridad
# ---------------------------------------------------------------------------
ACTUAL=$(sha256sum "$INSTALLER" | awk '{print $1}')
EXPECTED="${MS_INSTALLER_SHA256:-}"

if [ -z "$EXPECTED" ]; then
    # Se intenta el .sha256 publicado; si no hay, se pide confirmación manual.
    if curl -fsSL --max-time 30 -o "$WORKDIR/installer.sha256" \
            "${MS_BASE}/installer/ms_install_offline.sh.sha256" 2>/dev/null; then
        EXPECTED=$(awk '{print $1}' "$WORKDIR/installer.sha256" | head -1)
        info "hash esperado leído de la release"
    fi
fi

if [ -n "$EXPECTED" ]; then
    if [ "$(echo "$EXPECTED" | tr 'A-F' 'a-f')" != "$ACTUAL" ]; then
        echo -e "${RED}NO COINCIDE${NC}"
        echo "  esperado : $EXPECTED"
        echo "  obtenido : $ACTUAL"
        die "el instalador NO es el que se publicó. No se ejecuta nada."
    fi
    info "sha256 verificado: $ACTUAL"
else
    warn "no hay hash publicado; verifica tú el archivo antes de continuar"
    warn "  sha256 obtenido: $ACTUAL"
fi

# ---------------------------------------------------------------------------
# 4 · Payload del panel
# ---------------------------------------------------------------------------
if [ -z "${MS_PAYLOAD_SHA256:-}" ]; then
    die "falta MS_PAYLOAD_SHA256 (hash del .tar.gz del panel). Calcula tú el hash:
       sha256sum ms_install_5.2.8.tar.gz
     y vuelve a lanzar:
       sudo MS_PAYLOAD_SHA256=<hash> bash $0"
fi

PAYLOAD="${MS_PAYLOAD:-}"
if [ -z "$PAYLOAD" ]; then
    for cand in ./ms_install_*.tar.gz ./ms_install.tar.gz; do
        [ -f "$cand" ] && PAYLOAD="$cand" && break
    done
fi
[ -n "$PAYLOAD" ] && [ -f "$PAYLOAD" ] || \
    die "no encuentro el .tar.gz del panel. Ponlo en el directorio actual o define MS_PAYLOAD"
PAYLOAD_ABS=$(cd "$(dirname "$PAYLOAD")" && pwd)/$(basename "$PAYLOAD")
PAYLOAD_REAL_SHA=$(sha256sum "$PAYLOAD_ABS" | awk '{print $1}')
if [ "${MS_PAYLOAD_SHA256,,}" != "$PAYLOAD_REAL_SHA" ]; then
    die "el hash del payload no coincide (esperado $MS_PAYLOAD_SHA256, obtenido $PAYLOAD_REAL_SHA)"
fi
info "payload verificado: $(basename "$PAYLOAD_ABS") ($(du -h "$PAYLOAD_ABS" | cut -f1))"

# ---------------------------------------------------------------------------
# 5 · Confirmación explícita
# ---------------------------------------------------------------------------
echo
info "resumen de lo que va a pasar:"
echo "   · instalar el panel en /home/midnightstreamer/iptv_midnight_streamer"
echo "   · crear usuario de sistema 'midnightstreamer' y su crontab"
echo "   · instalar/reconfigurar MariaDB (puerto 7999, solo loopback)"
echo "   · generar password de root de BD y del panel aleatorias"
echo "   · escribir /root/.midnightstreamer.credentials (0600)"
echo "   · NO desactivar SELinux · NO tocar sudoers · NO tocar los logs del sistema"
echo
if [ "${MS_YES:-0}" != "1" ]; then
    read -r -p "¿Continuar? escribe 'instalar' para confirmar: " ANSWER
    [ "$ANSWER" = "instalar" ] || { echo "cancelado."; exit 3; }
fi

# ---------------------------------------------------------------------------
# 6 · Ejecutar
# ---------------------------------------------------------------------------
info "ejecutando instalador…"
cd "$(dirname "$PAYLOAD_ABS")" || die "no se pudo entrar en $(dirname "$PAYLOAD_ABS")"
MS_PAYLOAD="$PAYLOAD_ABS" MS_PAYLOAD_SHA256="$MS_PAYLOAD_SHA256" \
    bash "$INSTALLER"
RC=$?

echo
if [ "$RC" -eq 0 ]; then
    echo -e "${GRN}==========================================================${NC}"
    echo -e "${GRN} instalación terminada${NC}"
    echo -e "${GRN}==========================================================${NC}"
    echo " credenciales: /root/.midnightstreamer.credentials  (chmod 600)"
    echo " panel:        http://<tu-ip>:8000/admin"
    echo
    echo " siguientes pasos:"
    echo "   1) cat /root/.midnightstreamer.credentials   y guarda las claves en un gestor"
    echo "   2) bash /root/vps_audit.sh --out /root/audit-postinstall.txt"
    echo "   3) si el panel va a estar en internet, pon delante un WAF/proxy TLS real"
    exit 0
else
    echo -e "${RED}el instalador terminó con código $RC${NC}" >&2
    echo "revisa:  journalctl -xe  ·  /var/log/syslog" >&2
    exit 4
fi
