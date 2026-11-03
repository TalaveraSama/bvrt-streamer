#!/usr/bin/env bash
#
# bvrt-streamer :: vps_audit.sh — auditoría READ-ONLY de un host con
# MidnightStreamer (o de cualquier host que sospeches comprometido).
#
# ESTE SCRIPT NO CAMBIA NADA. Solo lee. No instala, no reinicia, no borra,
# no toca cron ni sudoers. Puedes correrlo en producción sin riesgo.
# Lo único que escribe es el informe en /root (o donde digas con --out).
#
# Uso (en el VPS, como root):
#   bash vps_audit.sh                       # informe a stdout
#   bash vps_audit.sh --out /root/audit.txt # informe a archivo
#   bash vps_audit.sh --payload /home/midnightstreamer/iptv_midnight_streamer --payload /var/www
#
# Pensado para compartir el resultado: reemplaza IPs por X.X.X.X antes de
# publicarlo, pero NO borres líneas: la ausencia de un dato también es un dato.
#
# Secciones: 0 identidad · 1 usuarios · 2 red · 3 servicios · 4 integridad
#            5 panel · 6 base de datos · 7 IOCs · 8 rootkits · 9 logs · 10 resumen
#
set -uo pipefail

OUT=""
PAYLOADS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --out)     OUT="${2:-}"; shift 2 ;;
        --payload) PAYLOADS+=("${2:-}"); shift 2 ;;
        -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "opción desconocida: $1" >&2; exit 2 ;;
    esac
done

# Rutas típicas del panel si no se pasan a mano
if [ "${#PAYLOADS[@]}" -eq 0 ]; then
    for p in /home/midnightstreamer/iptv_midnight_streamer /home/midnightstreamer \
             /var/www /var/www/html /opt; do
        [ -d "$p" ] && PAYLOADS+=("$p")
    done
fi

redact() { sed -E 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/X.X.X.X/g' \
                 | sed -E 's/([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/\1@DOMINIO/g'; }

S() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
sub() { printf '\n-- %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

run() { # ejecuta y marca vacío explícitamente (la ausencia de salida es dato)
    local out
    out=$("$@" 2>&1) || true
    if [ -z "$out" ]; then echo "  (sin salida)"; else printf '%s\n' "$out" | sed 's/^/  /'; fi
}
try() { echo "  \$ $*"; run "$@"; }

report() {
S "0 · IDENTIDAD DEL HOST"
try hostname -f
try date -u
[ -r /etc/os-release ] && . /etc/os-release && echo "  distro: ${PRETTY_NAME:-?}"
try uname -a
try uptime
echo "  virtualización: $(systemd-detect-virt 2>/dev/null || echo '?')"
echo "  hora sincronizada: $(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo '?')"

S "1 · USUARIOS Y ACCESO"
sub "usuarios con shell"
echo "  $(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1"("$3")"}' /etc/passwd | tr '\n' ' ')"
sub "usuarios con UID 0 (debe ser SOLO root)"
echo "  $(awk -F: '$3==0 {print $1}' /etc/passwd | tr '\n' ' ')"
sub "logins recientes (last -20)"
try last -20 -F
sub "intentos fallidos (últimos 10)"
try lastb -10 2>/dev/null
sub "claves SSH autorizadas (todas las cuentas)"
for h in /root /home/*; do
    [ -f "$h/.ssh/authorized_keys" ] || continue
    echo "  $h/.ssh/authorized_keys: $(grep -cE '^(ssh-|ecdsa-|sk-)' "$h/.ssh/authorized_keys") clave(s)"
    awk '{print "    " $1 " …" $NF}' "$h/.ssh/authorized_keys"
    stat -c '    perms %a %U:%G' "$h/.ssh" "$h/.ssh/authorized_keys"
done
sub "reglas sudo NOPASSWD (aquí se vio H-11)"
try grep -rnE 'NOPASSWD|^[^#]*ALL[[:space:]]*=[[:space:]]*\(ALL\)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
sub "cuentas con password vacío"
echo "  $(awk -F: '$2=="" {print $1}' /etc/shadow | tr '\n' ' ')(nada entre paréntesis = bien)"
sub "grupos privilegiados"
for g in sudo wheel docker adm systemd-journal; do
    echo "  $g: $(getent group "$g" | cut -d: -f4)"
done

S "2 · RED"
sub "puertos escuchando"
if have ss; then try ss -tulpn; else try netstat -tulpn; fi
sub "puertos que NO deberían estar abiertos (panel/MariaDB)"
if have ss; then
    ss -tlnp 2>/dev/null | grep -E ':(3306|7999|8000|8001|8002)\b' | sed 's/^/  /' || echo "  ninguno de 3306/7999/8000/8001/8002 escuchando"
fi
sub "reglas de firewall"
have iptables && try iptables -S
have ufw && try ufw status verbose
have nft && try nft list ruleset
sub "conexiones establecidas sospechosas (no privadas)"
if have ss; then
    ss -tnp state established 2>/dev/null | grep -vE '127\.0\.0\.1|::1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.' | sed 's/^/  /' || echo "  (ninguna)"
fi

S "3 · SERVICIOS Y PERSISTENCIA"
sub "servicios habilitados"
try systemctl list-unit-files --state=enabled --no-pager
sub "cron: root"
try crontab -l
sub "cron: usuario del panel"
try crontab -u midnightstreamer -l
sub "/etc/cron*/*"
try grep -rIl '' /etc/cron.d /etc/cron.hourly /etc/cron.daily 2>/dev/null
try grep -rInE 'curl|wget|bash -i|nc |base64|/dev/tcp' /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null
sub "rc.local / init.d propios"
try ls -la /etc/rc.local /etc/init.d/
sub "systemd units sospechosas (creadas fuera de paquetes)"
try find /etc/systemd/system /lib/systemd/system -name '*.service' -newermt '-400 days' 2>/dev/null
sub "¿queda la regla de rsyslog que silenciaba cron/sudo? (H-12)"
if [ -f /etc/rsyslog.d/00-midnightstreamer.conf ]; then
    echo "  ¡PRESENTE! contiene:"
    sed 's/^/    /' /etc/rsyslog.d/00-midnightstreamer.conf
else
    echo "  ausente (bien)"
fi
sub "¿siguen los repos apt sin firma? (H-06)"
if [ -f /etc/apt/sources.list.d/midnightstreamer.list ]; then
    echo "  ¡PRESENTE!"; grep -h . /etc/apt/sources.list.d/midnightstreamer.list | sed 's/^/    /'
else
    echo "  ausente (bien)"
fi

S "4 · INTEGRIDAD DEL SISTEMA"
sub "ld.so.preload (indicador de rootkit)"
if [ -s /etc/ld.so.preload ]; then echo "  ¡NO VACÍO!"; sed 's/^/    /' /etc/ld.so.preload
else echo "  vacío o ausente (bien)"; fi
sub "SUID/SGID (fuera de rutas estándar)"
try find / -xdev -type f -perm -4000 -o -xdev -type f -perm -2000 2>/dev/null
sub "ejecutables en /tmp /var/tmp /dev/shm"
try find /tmp /var/tmp /dev/shm -type f \( -perm -u+x -o -name '*.sh' -o -name '*.py' \) 2>/dev/null
sub "verificación de paquetes (dpkg -V; puede tardar)"
if have dpkg; then
    OUTV=$(dpkg -V 2>/dev/null | head -40); [ -z "$OUTV" ] && echo "  sin cambios detectados" || printf '%s\n' "$OUTV" | sed 's/^/  /'
fi
sub "claves y certificados del panel"
for f in $(find /home /var/www -maxdepth 6 \( -name 'server.key' -o -name 'server-cert.pem' -o -name 'server-key.pem' \) 2>/dev/null); do
    stat -c '  %a %U:%G %n' "$f"
done

S "5 · PANEL Y PAYLOAD"
echo "  rutas analizadas: ${PAYLOADS[*]:-ninguna}"
for p in "${PAYLOADS[@]}"; do
    [ -d "$p" ] || continue
    sub "$p"
    try du -sh "$p"
    try find "$p" -maxdepth 1 -mindepth 1 -printf '%M %u:%g %10s  %f\n'
    sub "config/license"
    for f in "$p/config" "$p/license" "$p/iptv_midnight_streamer/config" "$p/iptv_midnight_streamer/license"; do
        [ -f "$f" ] && stat -c '  %a %U:%G %10s bytes  %n' "$f" && \
            echo "    sha256 $(sha256sum "$f" | cut -d' ' -f1)"
    done
    sub "PHP modificado en los últimos 30 días"
    try find "$p" -name '*.php' -newermt '-30 days' -printf '%TY-%Tm-%Td %10s  %p\n' 2>/dev/null
    sub "webshells / eval / base64 (rápido)"
    grep -rIl --include='*.php' -E 'eval[[:space:]]*\(|base64_decode|gzinflate|str_rot13|assert[[:space:]]*\([[:space:]]*\$|\\\$_(POST|GET|REQUEST)\[[^]]+\][^(]*\(' "$p" 2>/dev/null | head -30 | sed 's/^/  /' || echo "  (sin coincidencias)"
    sub "callbacks a dominios del panel"
    grep -rIn --include='*.php' -E 'valut\.iptvtools\.io|iptvtools\.b-cdn\.net|midnightstreamer\.com' "$p" 2>/dev/null | head -20 | sed 's/^/  /' || echo "  (sin coincidencias)"
    sub "credenciales hardcodeadas conocidas"
    grep -rIn -E 'pglauD4F0L|hn6SImdyx7|dtqVa5xwoU|02230129b6ad71bae0292032450090cd' "$p" 2>/dev/null | head -10 | sed 's/^/  /' || echo "  (sin coincidencias)"
    sub "php.ini: disable_functions y open_basedir"
    grep -rIhE '^[[:space:]]*(disable_functions|open_basedir|allow_url_include|expose_php)' "$p" 2>/dev/null | sort -u | sed 's/^/  /' || echo "  (no encontrado)"
    sub "hash de los binarios del panel"
    for b in php/bin/php php/bin/php-fpm bin/ffmpeg bin/ffprobe; do
        [ -f "$p/$b" ] && echo "  $(sha256sum "$p/$b")"
    done
done

S "6 · BASE DE DATOS"
if have mysql; then
    sub "usuarios MySQL y hosts permitidos (lo crítico es @'%')"
    try mysql --protocol=socket -u root -e "SELECT user,host,plugin FROM mysql.user ORDER BY user,host;" 2>/dev/null
    sub "grants del usuario del panel"
    try mysql --protocol=socket -u root -e "SHOW GRANTS FOR 'midnightstreamer'@'%';" 2>/dev/null
    try mysql --protocol=socket -u root -e "SHOW GRANTS FOR 'midnightstreamer'@'localhost';" 2>/dev/null
    sub "¿root sin password o con 'iptv'?"
    mysql --protocol=socket -u root -e 'SELECT 1' >/dev/null 2>&1 && echo "  ¡root entra SIN password por socket!"
    MYSQL_PWD=iptv mysql --protocol=socket -u root -e 'SELECT 1' >/dev/null 2>&1 && echo "  ¡root tiene la password 'iptv'!"
    sub "bind-address"
    grep -rhE '^[[:space:]]*bind-address' /etc/mysql/ 2>/dev/null | sed 's/^/  /' || echo "  (sin bind-address explícito: por defecto 127.0.0.1 en MariaDB reciente, 0.0.0.0 en otras)"
else
    echo "  mysql no instalado o no en PATH"
fi

S "7 · INDICADORES DE COMPROMISO (IOCs)"
sub "procesos con nombre sospechoso"
ps aux 2>/dev/null | grep -vE 'grep|ps aux|\[.*\]$' | grep -E 'kworker|\.\/[a-z]{6,}|/tmp/|/dev/shm/|python -c|perl -e|nc -[el]|socat|xmrig|kinsing|kdevtmpfsi' | sed 's/^/  /' || echo "  (nada evidente)"
sub "procesos con conexiones a IPs públicas"
if have ss; then
    ss -tnp 2>/dev/null | awk 'NR>1 {print $5, $6}' | grep -vE '127\.0\.0\.1|::1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.' | sort -u | head -30 | sed 's/^/  /'
fi
sub "archivos con setuid creados recientemente"
try find / -xdev -type f -perm -4000 -newermt '-90 days' 2>/dev/null
sub "usuarios creados recientemente"
try awk -F: '$3>=1000 && $3<65534 {print $1, $3, $6, $7}' /etc/passwd
try ls -la --time-style=long-iso /home 2>/dev/null
sub "paquetes instalados hoy"
if have dpkg; then
    grep "$(date +%Y-%m-%d)" /var/log/dpkg.log 2>/dev/null | tail -20 | sed 's/^/  /' || echo "  (nada)"
fi
sub "IPs que han hecho login SSH con éxito"
grep -hE 'Accepted (password|publickey)' /var/log/auth.log /var/log/secure 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head -20 \
    | sed 's/^/  /' || echo "  (sin registros de auth: ¿los borró el instalador? H-12)"

S "8 · ROOTKITS Y MÓDULOS"
sub "módulos del kernel fuera de lo esperado"
try lsmod
sub "integridad de binarios críticos"
for b in /usr/bin/ssh /usr/sbin/sshd /bin/bash /usr/bin/sudo /usr/bin/curl /usr/sbin/cron /usr/sbin/rsyslogd; do
    [ -f "$b" ] && echo "  $(sha256sum "$b")"
done
sub "tareas ocultas en /etc"
try find /etc -name '*rc*' -newermt '-180 days' -type f 2>/dev/null

S "9 · LOGS"
sub "tamaño de logs (muy pequeños = borrados)"
try ls -la /var/log/
sub "huecos en syslog/auth"
try grep -cE '.' /var/log/auth.log 2>/dev/null
sub "journal: últimos arranques"
try journalctl --list-boots 2>/dev/null
sub "journal: errores recientes"
try journalctl -p err -n 20 --no-pager 2>/dev/null

S "10 · RESUMEN"
echo "  Este informe es de solo lectura. Nada se ha modificado."
echo "  Revisa en este orden:"
echo "    1) UID 0 != solo root · authorized_keys desconocidas · NOPASSWD"
echo "    2) @'%' en MySQL y root con 'iptv'"
echo "    3) ld.so.preload no vacío"
echo "    4) webshells / eval en el docroot"
echo "    5) logs de cron y sudo ausentes (H-12: el instalador los tiraba)"
}

if [ -n "$OUT" ]; then
    report > "$OUT" 2>&1
    chmod 600 "$OUT"
    echo "informe en $OUT"
    echo "antes de compartirlo:  sed -i -E 's/([0-9]{1,3}\\.){3}[0-9]{1,3}/X.X.X.X/g' $OUT"
else
    report
fi
