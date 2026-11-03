#!/usr/bin/env bash
#
# bvrt-streamer :: scan_payload.sh
# ---------------------------------------------------------------------------
# Auditoría estática del payload de MidnightStreamer (el .tar.gz extraído).
# Está pensado para correr sobre una instalación recién extraída y SIN
# arrancar, porque detecta webshells, callbacks, backdoors y persistencia.
#
# Uso:
#   ./tools/scan_payload.sh <directorio>
#   ./tools/scan_payload.sh <directorio> --json > informe.json
#   ./tools/scan_payload.sh <directorio> --strict   # exit 1 ante medium
#
# Salida: hallazgos con severidad (critical/high/medium/info) y ruta:línea.
# Exit:   0 limpio, 1 hallazgos critical (o medium con --strict), 2 uso.
#
# IMPORTANTE: es análisis estático. No ejecuta nada del payload.
# ---------------------------------------------------------------------------
set -uo pipefail

TARGET="${1:-}"
JSON=0
STRICT=0
shift 2>/dev/null || true
for arg in "$@"; do
    case "$arg" in
        --json)   JSON=1 ;;
        --strict) STRICT=1 ;;
        *) echo "opción desconocida: $arg" >&2; exit 2 ;;
    esac
done

if [ -z "$TARGET" ] || [ ! -d "$TARGET" ]; then
    echo "uso: $0 <directorio-extraido> [--json] [--strict]" >&2
    exit 2
fi
TARGET=$(cd "$TARGET" && pwd)

CRIT=0; HIGH=0; MED=0; INFO=0
TMP=$(mktemp)
trap 'rm -f "$TMP" "$FINDINGS_FILE" 2>/dev/null' EXIT

FINDINGS_FILE=$(mktemp)
emit() { # emit <sev> <id> <desc> [detalle...]
    local sev="$1" id="$2" desc="$3"; shift 3
    case "$sev" in
        critical) CRIT=$((CRIT+1)) ;;
        high)     HIGH=$((HIGH+1)) ;;
        medium)   MED=$((MED+1)) ;;
        *)        INFO=$((INFO+1)) ;;
    esac
    if [ "$JSON" = "1" ]; then
        local details="" first=1 l esc
        for l in "$@"; do
            esc=$(printf '%s' "$l" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | tr -d '\r\n')
            if [ "$first" = "1" ]; then details="$esc"; first=0; else details="$details|$esc"; fi
        done
        printf '%s\n' "{\"severity\":\"$sev\",\"id\":\"$id\",\"check\":\"$desc\",\"details\":\"$details\"}" >> "$FINDINGS_FILE"
    else
        printf '[%-8s] %-6s %s\n' "$sev" "$id" "$desc"
        local n=0
        for l in "$@"; do
            n=$((n+1)); [ "$n" -gt 40 ] && { echo "           ... (truncado)"; break; }
            printf '           %s\n' "$l"
        done
    fi
}

# ---------------------------------------------------------------------------
# Inventario
# ---------------------------------------------------------------------------
mapfile -t PHP_FILES < <(find "$TARGET" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php5' -o -name '*.phar' -o -name '*.inc' \) -print0 2>/dev/null | tr '\0' '\n')
mapfile -t EXEC_FILES < <(find "$TARGET" -type f -perm -u+x -print0 2>/dev/null | tr '\0' '\n')
mapfile -t SUID_FILES < <(find "$TARGET" -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null | tr '\0' '\n')
mapfile -t WW_FILES < <(find "$TARGET" -type f -perm -o+w -print0 2>/dev/null | tr '\0' '\n')

if [ "$JSON" = "1" ]; then
    : > "$FINDINGS_FILE"
else
    echo "=================================================================="
    echo " bvrt-streamer · escáner de payload"
    echo " objetivo : $TARGET"
    echo " archivos : $(find "$TARGET" -type f 2>/dev/null | wc -l) totales, ${#PHP_FILES[@]} PHP, ${#EXEC_FILES[@]} ejecutables"
    echo " fecha    : $(date -u +%FT%TZ)"
    echo "=================================================================="
    echo
fi

# ---------------------------------------------------------------------------
# C-01/Ejecución dinámica de código en PHP (patrón de webshell)
# ---------------------------------------------------------------------------
if [ "${#PHP_FILES[@]}" -gt 0 ]; then
    PAT='eval[[:space:]]*\(|assert[[:space:]]*\([[:space:]]*\$|create_function[[:space:]]*\(|preg_replace[[:space:]]*\(.*/e[^a-z]|call_user_func[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)'
    HITS=$(printf '%s\0' "${PHP_FILES[@]}" | xargs -0 -n1 grep -aInHE "$PAT" 2>/dev/null | head -60)
    [ -n "$HITS" ] && emit critical C-01 "ejecución dinámica de código (eval/assert/call_user_func con input)" $(echo "$HITS")

    # Webshell de una línea: mucho base64/eval en archivos pequeños
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        sz=$(wc -c < "$f")
        if [ "$sz" -lt 4000 ] && grep -aqE '\$_(POST|GET|REQUEST|COOKIE|SERVER)\[' "$f" 2>/dev/null; then
            if grep -aqE 'base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|pack\(|chr\([0-9]' "$f" 2>/dev/null; then
                emit critical C-02 "posible webshell de una línea" "$f (${sz}b)"
            fi
        fi
    done < <(printf '%s\n' "${PHP_FILES[@]}")

    PAT2='\$_FILES\[[^]]+\]\[[^]]+\].*(move_uploaded_file|copy|rename)|system[[:space:]]*\(|passthru[[:space:]]*\(|shell_exec[[:space:]]*\(|popen[[:space:]]*\(|proc_open[[:space:]]*\(|pcntl_exec'
    HITS=$(printf '%s\0' "${PHP_FILES[@]}" | xargs -0 -n1 grep -aInHE "$PAT2" 2>/dev/null | head -60)
    [ -n "$HITS" ] && emit high C-03 "ejecución de comandos del sistema desde PHP" $(echo "$HITS")

    # Concatenación de chr() / cadenas hex: ofuscación clásica
    HITS=$(printf '%s\0' "${PHP_FILES[@]}" | xargs -0 -n1 grep -aInHE '(chr\([0-9]{1,3}\)[[:space:]]*\.[[:space:]]*){5,}|(\\x[0-9a-fA-F]{2}){12,}' 2>/dev/null | head -40)
    [ -n "$HITS" ] && emit high C-04 "cadenas ofuscadas (chr()/hex) en PHP" $(echo "$HITS")
fi

# ---------------------------------------------------------------------------
# C-05 Blobs base64 grandes (payload empaquetado)
# ---------------------------------------------------------------------------
HITS=$(find "$TARGET" -type f \( -name '*.php' -o -name '*.inc' -o -name '*.sh' \) -size -2M -print0 2>/dev/null \
    | xargs -0 -n1 grep -aInHE "[A-Za-z0-9+/]{200,}={0,2}" 2>/dev/null | head -40)
[ -n "$HITS" ] && emit high C-05 "bloques base64 largos (posible payload empaquetado)" $(echo "$HITS")

# ---------------------------------------------------------------------------
# C-06 Credenciales y claves hardcodeadas conocidas del panel
# ---------------------------------------------------------------------------
KNOWN_PAT='pglauD4F0L|hn6SImdyx7|02230129b6ad71bae0292032450090cd|dtqVa5xwoU|2cd71063c6a79832cdfeb889f4c072e425067fe2'
HITS=$(grep -aInHE "$KNOWN_PAT" -r "$TARGET" 2>/dev/null | head -40)
[ -n "$HITS" ] && emit critical C-06 "credenciales/claves hardcodeadas conocidas" $(echo "$HITS")

HITS=$(grep -aInHE "password[[:space:]]*=[[:space:]]*['\"][^'\"]{1,20}['\"]" -r "$TARGET" --include='*.php' 2>/dev/null \
    | grep -avE "password['\"]?[[:space:]]*=[[:space:]]*['\"]{2}|password.*\\\$|=== *'password'" | head -40)
[ -n "$HITS" ] && emit medium C-07 "posibles passwords literales en código" $(echo "$HITS")

# ---------------------------------------------------------------------------
# C-08 Callbacks a red externa
# ---------------------------------------------------------------------------
NET_PAT='fsockopen[[:space:]]*\(|stream_socket_client[[:space:]]*\(|curl_init[[:space:]]*\(|file_get_contents[[:space:]]*\([[:space:]]*["'"'"']https?://|new[[:space:]]+SoapClient'
HITS=$(printf '%s\0' "${PHP_FILES[@]}" 2>/dev/null | xargs -0 -n1 grep -aInHE "$NET_PAT" 2>/dev/null | head -60)
[ -n "$HITS" ] && emit high C-08 "llamadas de red salientes desde PHP (auditar destino)" $(echo "$HITS")

DOMAINS='valut\.iptvtools\.io|iptvtools\.b-cdn\.net|midnightstreamer\.com|download\.midnightstreamer\.com'
HITS=$(grep -aInHE "$DOMAINS" -r "$TARGET" 2>/dev/null | head -40)
[ -n "$HITS" ] && emit critical C-09 "referencias a dominios de licencia/CDN del panel" $(echo "$HITS")

# Cualquier URL hardcodeada dentro de código PHP
HITS=$(printf '%s\0' "${PHP_FILES[@]}" 2>/dev/null \
    | xargs -0 -n1 grep -aInHE "https?://[a-zA-Z0-9._-]+" 2>/dev/null \
    | grep -avE "w3\.org|schema\.org|localhost|127\.0\.0\.1|example\.(com|org)|xmlns|github\.com/(MDS|TalaveraSama)|nginx\.org|php\.net|mariadb\.org|mysql\.com|json-schema|webrtc\.org" | head -60)
[ -n "$HITS" ] && emit medium C-10 "URLs hardcodeadas en PHP (revisar una a una)" $(echo "$HITS")

# ---------------------------------------------------------------------------
# C-11 Persistencia: cron, inicio, autorización de claves
# ---------------------------------------------------------------------------
HITS=$(grep -aInHE 'crontab|/etc/cron\.|\.bashrc|\.profile|authorized_keys|rc\.local|systemd/system' -r "$TARGET" 2>/dev/null | head -60)
[ -n "$HITS" ] && emit high C-11 "instalación de persistencia desde el payload" $(echo "$HITS")

# ---------------------------------------------------------------------------
# C-12 Escalada de privilegios dentro del payload
# ---------------------------------------------------------------------------
HITS=$(grep -aInHE 'NOPASSWD|chmod[[:space:]]+([0-7]*7[0-7]7|u\+s|\+s)|setenforce|apparmor_parser.*complain' -r "$TARGET" 2>/dev/null | head -40)
[ -n "$HITS" ] && emit high C-12 "cambios de privilegios/permisos peligrosos" $(echo "$HITS")

# ---------------------------------------------------------------------------
# C-13 Permisos de archivo anómalos
# ---------------------------------------------------------------------------
[ "${#SUID_FILES[@]}" -gt 0 ] && emit critical C-13 "archivos con bit SUID/SGID" "${SUID_FILES[@]}"
if [ "${#WW_FILES[@]}" -gt 0 ]; then
    emit medium C-14 "archivos escribibles por cualquiera" $(printf '%s\n' "${WW_FILES[@]}" | head -40)
fi

# PHP dentro de directorios que deberían ser solo de datos
BAD_DIRS=$(printf '%s\n' "${PHP_FILES[@]}" | grep -aE '/(streams|tmp|uploads?|cache|logs?|images?)/[^/]*\.(php|phtml)$' | head -40)
[ -n "$BAD_DIRS" ] && emit critical C-15 "PHP ejecutable en directorios de datos" $(echo "$BAD_DIRS")

# ---------------------------------------------------------------------------
# C-16 Binarios: URLs y cadenas sospechosas embebidas
# ---------------------------------------------------------------------------
if command -v strings >/dev/null 2>&1; then
    N=0
    while IFS= read -r bin; do
        [ -z "$bin" ] && continue
        case "$(basename "$bin")" in
            php|php-fpm|ffmpeg|ffprobe|nginx) ;;
            *) continue ;;
        esac
        N=$((N+1)); [ "$N" -gt 8 ] && break
        H=$(strings -a "$bin" 2>/dev/null | grep -aE "$DOMAINS|/[a-z0-9_]+\.php\?[a-z]+=|https?://[a-z0-9.-]+/api" | head -10)
        [ -n "$H" ] && emit high C-16 "cadenas de red embebidas en binario" "$bin" $(echo "$H" | sed 's/^/  /')
    done < <(find "$TARGET" -type f \( -name 'php' -o -name 'php-fpm' -o -name 'ffmpeg*' -o -name 'ffprobe*' -o -name 'nginx*' \) 2>/dev/null)
fi

# ---------------------------------------------------------------------------
# C-17 Archivos ocultos y nombres sospechosos
# ---------------------------------------------------------------------------
HIDDEN=$(find "$TARGET" -type f -name '.*' ! -name '.htaccess' ! -name '.gitignore' ! -name '.user.ini' 2>/dev/null | head -40)
[ -n "$HIDDEN" ] && emit medium C-17 "archivos ocultos (revisar)" $(echo "$HIDDEN")

ODD=$(find "$TARGET" -type f \( -name '*.php.*' -o -name '*.jpg.php' -o -name '*.png.php' -o -name '*;*' -o -name '*.php%*' \) 2>/dev/null | head -40)
[ -n "$ODD" ] && emit critical C-18 "nombres de archivo con doble extensión/inyección" $(echo "$ODD")

# ---------------------------------------------------------------------------
# C-19 Diferencias con el upstream esperado (si hay lista de hashes)
# ---------------------------------------------------------------------------
if [ -f "$(dirname "$0")/../tools/payload.sha256" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        ( cd "$TARGET" && sha256sum -c "$(dirname "$0")/../tools/payload.sha256" --quiet 2>&1 | head -40 )
    fi
fi

# ---------------------------------------------------------------------------
# C-20 config/license: blobs cifrados ≠ documentados
# ---------------------------------------------------------------------------
for f in config license; do
    p="$TARGET/$f"
    if [ -f "$p" ]; then
        sz=$(wc -c < "$p")
        emit info C-20 "blob '$f' presente (${sz}b) — revisar de dónde sale y a dónde va" "$p"
    fi
done

# ---------------------------------------------------------------------------
# Resumen
# ---------------------------------------------------------------------------
if [ "$JSON" = "1" ]; then
    printf '{\n  "target": "%s",\n  "scanned_at": "%s",\n  "summary": {"critical": %d, "high": %d, "medium": %d, "info": %d},\n  "findings": [\n' \
        "$TARGET" "$(date -u +%FT%TZ)" "$CRIT" "$HIGH" "$MED" "$INFO"
    awk 'NR>1{printf ",\n"} {printf "    %s", $0}' "$FINDINGS_FILE"
    printf '\n  ]\n}\n'
else
    echo
    echo "------------------------------------------------------------------"
    printf ' crítico: %d   alto: %d   medio: %d   info: %d\n' "$CRIT" "$HIGH" "$MED" "$INFO"
    if [ "$CRIT" -gt 0 ]; then
        echo " RESULTADO: NO INSTALAR hasta revisar los hallazgos críticos."
    elif [ "$HIGH" -gt 0 ]; then
        echo " RESULTADO: revisar los hallazgos altos antes de arrancar el panel."
    else
        echo " RESULTADO: sin hallazgos críticos en análisis estático."
        echo "            (no sustituye a revisar manualmente los informes de C-10/C-20)"
    fi
    echo "------------------------------------------------------------------"
fi

[ "$CRIT" -gt 0 ] && exit 1
[ "$STRICT" = "1" ] && [ "$((HIGH+MED))" -gt 0 ] && exit 1
exit 0
