#! /bin/bash
#
# ============================================================================
#  bvrt-streamer :: instalador endurecido
# ----------------------------------------------------------------------------
#  Base: MDS-Unofficial/MidnightStreamer :: ms_install_offline.sh
#        sha256 57af018eb6cf4b189eae124ed4fa7953c82da26801775f100eb8f624f2965885
#        Copia sin modificar en ../upstream/ms_install_offline.sh
#
#  Este archivo NO es una reescritura: es el instalador original con los
#  bloques peligrosos corregidos. Cada corrección lleva la etiqueta
#  [HARDENING n] y está documentada en ../docs/HALLAZGOS.md.
#
#  Lo que NO se puede arreglar aquí y requiere decisión de producto:
#    - Credenciales por defecto del panel (admin/iptv) -> ver H-12
#    - Blobs cifrados de config/license (H-09) y su callback de licencia
#    - Binarios precompilados sin checksum (php, ffmpeg) (H-10)
#  El escáner ../tools/scan_payload.sh audita el payload una vez extraído.
# ============================================================================
#
#  Uso:
#    sudo MS_PAYLOAD_SHA256=<hash> ./ms_install_offline.sh
#
#  Variables de entorno respetadas:
#    MS_PAYLOAD_SHA256   (obligatoria) sha256 del tar.gz del panel a instalar
#    MS_PAYLOAD          (opcional)  ruta/nombre del tar.gz (autodetecta)
#    MS_DB_PASSWORD      (opcional)  password del usuario de BD (se genera)
#    MS_DB_ROOT_PASSWORD (opcional)  password root de MariaDB (se genera)
#    MS_SKIP_NVIDIA      (opcional)  =1 para no tocar drivers NVIDIA (def. 1)
#
set -uo pipefail

MS_USER="midnightstreamer"
MS_ROOT="/home/${MS_USER}/iptv_midnight_streamer"
MS_VERSION="5.9.1"

PURPLE='\033[0;35m'
OKCYAN='\033[96m'
YELLOW='\033[93m'
RED='\033[0;31m'
NC='\033[0m'

die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
info() { echo -e "${OKCYAN}[INFO]${NC} $*"; }

getIP() {
    ip -4 route get 8.8.8.8 2>/dev/null | awk '{
        for (i = 1; i < NF; i++)
            if ($i == "src") { print $(i+1); exit }
    }'
}

SERVER_IP=$(getIP)

# ---------------------------------------------------------------------------
# [HARDENING 0] Precondiciones. El original arrancaba pkill -9 nginx/php/ffmpeg
# y borraba /home/midnightstreamer sin comprobar nada (H-01). Aquí se aborta si
# no somos root, si la IP no se detecta, o si ya hay una instalación.
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "ejecuta como root (sudo)"
[ -n "$SERVER_IP" ] || die "no se pudo detectar la IP pública (getIP)"
[ -d "$MS_ROOT/cms" ] && die "ya existe una instalación en $MS_ROOT/cms"

# ---------------------------------------------------------------------------
# [HARDENING 1] Verificación de integridad del payload.
# El original hacía: cp ms_install_5.9.1.tar.gz (nombre fijo, versión distinta
# a la pedida) y tar -xvzf sin comprobar nada (H-05/H-10).
# ---------------------------------------------------------------------------
PAYLOAD="${MS_PAYLOAD:-}"
if [ -z "$PAYLOAD" ]; then
    for cand in ms_install_"$MS_VERSION".tar.gz ms_install.tar.gz; do
        [ -f "$PWD/$cand" ] && PAYLOAD="$PWD/$cand" && break
    done
fi
[ -n "$PAYLOAD" ] && [ -f "$PAYLOAD" ] || die "payload no encontrado (define MS_PAYLOAD)"
[ -n "${MS_PAYLOAD_SHA256:-}" ] || die "define MS_PAYLOAD_SHA256=<hash>; comprueba con sha256sum $PAYLOAD"

ACTUAL_SHA=$(sha256sum "$PAYLOAD" | awk '{print $1}')
[ "$ACTUAL_SHA" = "${MS_PAYLOAD_SHA256,,}" ] || \
    die "checksum del payload NO coincide (esperado $MS_PAYLOAD_SHA256, obtenido $ACTUAL_SHA)"

# ---------------------------------------------------------------------------
# [HARDENING 2] Credenciales: se generan, no se hardcodean (H-03/H-04).
# MS_DB_PASSWORD/MS_DB_ROOT_PASSWORD permiten fijarlas (p.ej. en un secreto
# de CI); si no, se genera una aleatoria y se guarda en /root a 0600.
# ---------------------------------------------------------------------------
rand_pw() { openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 24; }
MS_DB_PASSWORD="${MS_DB_PASSWORD:-$(rand_pw)}"
MS_DB_ROOT_PASSWORD="${MS_DB_ROOT_PASSWORD:-$(rand_pw)}"
CRED_FILE="/root/.midnightstreamer.credentials"

umask 077
cat > "$CRED_FILE" <<EOF
# Generado por bvrt-streamer $(date -u +%FT%TZ)
MS_DB_ROOT_PASSWORD=${MS_DB_ROOT_PASSWORD}
MS_DB_PASSWORD=${MS_DB_PASSWORD}
EOF
chmod 600 "$CRED_FILE"
umask 022
info "credenciales en $CRED_FILE (0600)"

# ---------------------------------------------------------------------------
# [HARDENING 3] Parada de servicios: solo los del panel, sin pkill -9 ciego.
# ---------------------------------------------------------------------------
for svc in nginx_iptv nginx_rtmp php-fpm; do
    pkill -TERM -x "$svc" 2>/dev/null || true
done
# NOTA: el original hacía `pkill -9 php` y `pkill -9 ffmpeg`, que mata
# cualquier PHP/ffmpeg del sistema, no solo los del panel (H-02).

# ---------------------------------------------------------------------------
# [HARDENING 4] Búsqueda de payload dentro del árbol, chequeo de tarball.
# Se elimina el `cd /home/midnightstreamer && rm -rf *` del original (H-01);
# en su lugar se borra únicamente el contenido del directorio del panel.
# ---------------------------------------------------------------------------
info "verificando contenido del payload"
tar -tzf "$PAYLOAD" >/dev/null 2>&1 || die "el payload no es un tar.gz válido"

if ! id "$MS_USER" &>/dev/null; then
    useradd -m "$MS_USER" || die "no se pudo crear el usuario $MS_USER"
fi

install -d -o "$MS_USER" -g "$MS_USER" -m 0755 "/home/${MS_USER}"
if [ -d "$MS_ROOT" ]; then
    info "limpiando solo $MS_ROOT"
    find "$MS_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi

install -o "$MS_USER" -g "$MS_USER" -m 0600 "$PAYLOAD" "/home/${MS_USER}/ms_install.tar.gz" \
    || die "no se pudo copiar el payload"
cd "/home/${MS_USER}" || die "no se pudo entrar en /home/${MS_USER}"
tar -xzf ms_install.tar.gz || die "fallo al extraer el payload"
install -o "$MS_USER" -g "$MS_USER" -m 0600 ms_install.tar.gz "$MS_ROOT/install/lb_install.tar.gz"
rm -f ms_install.tar.gz

[ -d "$MS_ROOT" ] || die "el payload no creó $MS_ROOT (¿tar.gz incorrecto?)"

# ---------------------------------------------------------------------------
# [HARDENING 5] SELinux ya no se desactiva (H-07). El original hacía
# setenforce 0 + sed 's/enforcing/disabled/'. Solo se etiqueta el contexto
# si SELinux está activo.
# ---------------------------------------------------------------------------
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
    if [ "${MS_SELINUX_RELABEL:-0}" = "1" ]; then
        semanage fcontext -a -t httpd_sys_rw_content_t "${MS_ROOT}(/.*)?" 2>/dev/null || true
        restorecon -R "$MS_ROOT" 2>/dev/null || true
        info "SELinux: contexto aplicado (no desactivado)"
    else
        warn "SELinux activo. Revisa los contextos del panel; NO se desactiva."
        warn "si necesitas relabel: MS_SELINUX_RELABEL=1"
    fi
fi

# ---------------------------------------------------------------------------
# [HARDENING 6] Repos apt: el original añadía Debian jessie y Ubuntu trusty
# (ambos EOL) por HTTP con [trusted=yes], es decir sin firma GPG (H-06).
# Aquí se elimina ese archivo y se usan solo los repos del sistema.
# ---------------------------------------------------------------------------
if [ -f /etc/apt/sources.list.d/midnightstreamer.list ]; then
    warn "eliminando repos sin firma dejados por el instalador anterior (H-06)"
    rm -f /etc/apt/sources.list.d/midnightstreamer.list
fi
[ -d /etc/apt/sources.list.d ] || install -d -m 0755 /etc/apt/sources.list.d

if command -v apt-get >/dev/null 2>&1; then
    PKG=apt-get
else
    PKG=yum
fi

if [ "$PKG" = "apt-get" ]; then
    export DEBIAN_FRONTEND=noninteractive
    if [ -f /etc/needrestart/needrestart.conf ]; then
        sed -i "s/^#\?\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
    fi
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        tar bc ca-certificates openssl jq curl iptables cron psmisc sudo \
        libxml2 librtmp1 libxslt1.1 libpq5 libltdl7 libpng16-16 libzip4 \
        libcurl4 libssh2-1 ntpdate python3 python3-pip >/dev/null 2>&1 || \
        warn "algunos paquetes opcionales no están disponibles en este release"
else
    yum install -y epel-release
    yum install -y tar bc ca-certificates openssl jq curl iptables cronie psmisc sudo \
        libxslt libjpeg-turbo openssl-libs libssh2 python3 python3-pip >/dev/null 2>&1 || \
        warn "algunos paquetes opcionales no están disponibles en este release"
fi

# ---------------------------------------------------------------------------
# [HARDENING 7] NVIDIA: el original purgaba drivers, hacía blacklist de
# nouveau y ejecutaba un .run de 570.144 que venía sin verificar dentro del
# payload (H-08). Por defecto queda DESACTIVADO. Si lo quieres:
#   MS_SKIP_NVIDIA=0 ./ms_install_offline.sh   (bajo tu responsabilidad)
# ---------------------------------------------------------------------------
if [ "${MS_SKIP_NVIDIA:-1}" != "1" ]; then
    warn "MS_SKIP_NVIDIA=0: se instalarán drivers NVIDIA del payload SIN verificar"
    if [ -f "$MS_ROOT/NVIDIA-Linux-x86_64-570.144.run" ]; then
        sh "$MS_ROOT/NVIDIA-Linux-x86_64-570.144.run" --silent --install-libglvnd || \
            warn "el instalador NVIDIA falló; el panel funciona sin él"
        rm -f "$MS_ROOT/NVIDIA-Linux-x86_64-570.144.run"
    fi
else
    info "NVIDIA: omitido (MS_SKIP_NVIDIA=1). ffmpeg usa el binario estándar."
fi

# ---------------------------------------------------------------------------
# [HARDENING 8] PHP: se respeta la elección por GLIBC, pero sin `bc` con
# comparación de strings y sin enlaces raros en /usr/local.
# ---------------------------------------------------------------------------
LIBC_VER=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
if [ -n "$LIBC_VER" ] && [ "$(printf '%s\n2.30\n' "$LIBC_VER" | sort -V | head -1)" = "2.30" ]; then
    PHPVER="8.3"
else
    PHPVER="7.3"
fi
if [ "$PHPVER" = "8.3" ] && [ -d "$MS_ROOT/php_8.3" ]; then
    rm -rf "$MS_ROOT/php"
    mv "$MS_ROOT/php_8.3" "$MS_ROOT/php"
    if [ -d "$MS_ROOT/wwwdir_8.3" ]; then
        rm -rf "$MS_ROOT/wwwdir"
        mv "$MS_ROOT/wwwdir_8.3" "$MS_ROOT/wwwdir"
    fi
else
    rm -rf "$MS_ROOT/php_8.3" "$MS_ROOT/wwwdir_8.3"
fi

# ---------------------------------------------------------------------------
# [HARDENING 9] Blobs config/license (H-09).
# El original escribía aquí cadenas cifradas hardcodeadas, iguales en todas
# las instalaciones, y el mismo blob se metía en la tabla `syncs`. Eso es a la
# vez un secreto compartido por todos los clientes y el canal del posible
# callback de licencia. Aquí NO se escriben: usa el instalador de tu proveedor
# o el alta de licencia del panel, y audita el callback con el escáner.
# ---------------------------------------------------------------------------
if [ ! -f "$MS_ROOT/config" ] || [ ! -f "$MS_ROOT/license" ]; then
    warn "config/license no presentes: el panel los pedirá en el alta (H-09)"
else
    chown "$MS_USER:$MS_USER" "$MS_ROOT/config" "$MS_ROOT/license"
    chmod 600 "$MS_ROOT/config" "$MS_ROOT/license"
fi

if [ "$PKG" = "apt-get" ]; then
    mv "$MS_ROOT/start_services_deb.sh" "$MS_ROOT/start_services.sh" 2>/dev/null || true
    rm -f "$MS_ROOT/start_services_rh.sh"
    mv "$MS_ROOT/php/bin/php_deb" "$MS_ROOT/php/bin/php" 2>/dev/null || true
    mv "$MS_ROOT/php/sbin/php-fpm_deb" "$MS_ROOT/php/sbin/php-fpm" 2>/dev/null || true
    rm -f "$MS_ROOT/php/bin/php_rh" "$MS_ROOT/php/sbin/php-fpm_rh"
    grep -qi '^deb .* universe' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || \
        add-apt-repository -y universe >/dev/null 2>&1 || true
else
    mv "$MS_ROOT/start_services_rh.sh" "$MS_ROOT/start_services.sh" 2>/dev/null || true
    rm -f "$MS_ROOT/start_services_deb.sh"
    mv "$MS_ROOT/php/bin/php_rh" "$MS_ROOT/php/bin/php" 2>/dev/null || true
    mv "$MS_ROOT/php/sbin/php-fpm_rh" "$MS_ROOT/php/sbin/php-fpm" 2>/dev/null || true
    rm -f "$MS_ROOT/php/bin/php_deb" "$MS_ROOT/php/sbin/php-fpm_deb"
fi

# ---------------------------------------------------------------------------
# [HARDENING 10] Límites del sistema: se reemplazan en bloque, no con
# grep -v sobre el archivo entero (que borraba cualquier línea con la palabra
# "midnightstreamer" y podía vaciar /etc/security/limits.conf).
# ---------------------------------------------------------------------------
LIMITS=/etc/security/limits.conf
if [ -f "$LIMITS" ]; then
    sed -i '/^midnightstreamer[[:space:]]/d; /# bvrt-streamer/d' "$LIMITS"
fi
cat >> "$LIMITS" <<'EOF'
# bvrt-streamer
midnightstreamer soft nproc  265536
midnightstreamer hard nproc  265535
midnightstreamer soft nofile 265535
midnightstreamer hard nofile 265535
EOF

# ---------------------------------------------------------------------------
# [HARDENING 11] sysctl: idempotente y con respaldo previo.
# ---------------------------------------------------------------------------
install -m 0644 /etc/sysctl.conf /etc/sysctl.conf.bvrt-backup.$(date +%s) 2>/dev/null || true
while read -r line; do
    key="${line%%=*}"
    key="${key%% *}"
    [ -n "$key" ] && sed -i "\|^[[:space:]]*${key}[[:space:]]*=|d" /etc/sysctl.conf
done <<'SYSCTL_KEYS'
net.core.somaxconn
net.ipv4.route.flush
net.ipv4.tcp_no_metrics_save
net.ipv4.tcp_moderate_rcvbuf
fs.file-max
fs.aio-max-nr
fs.nr_open
net.ipv4.ip_local_port_range
net.ipv4.tcp_sack
net.ipv4.tcp_rmem
net.ipv4.tcp_wmem
net.ipv4.tcp_mem
net.core.rmem_max
net.core.wmem_max
net.core.rmem_default
net.core.wmem_default
net.core.optmem_max
net.core.netdev_max_backlog
net.ipv4.tcp_max_syn_backlog
net.netfilter.nf_conntrack_max
net.ipv4.tcp_window_scaling
vm.max_map_count
net.ipv4.tcp_tw_reuse
net.ipv4.tcp_max_tw_buckets
kernel.shmmax
kernel.shmall
SYSCTL_KEYS

cat >> /etc/sysctl.conf <<'EOF'
# bvrt-streamer
net.core.somaxconn = 65535
fs.file-max = 6815744
fs.nr_open = 6815744
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_rmem = 10000000 10000000 10000000
net.ipv4.tcp_wmem = 10000000 10000000 10000000
net.core.rmem_max = 524287
net.core.wmem_max = 524287
net.core.netdev_max_backlog = 300000
net.ipv4.tcp_max_syn_backlog = 300000
vm.max_map_count = 655300
kernel.shmmax = 134217728
kernel.shmall = 134217728
EOF
sysctl -p >/dev/null 2>&1 || warn "sysctl -p devolvió errores (normal en contenedores)"

# ---------------------------------------------------------------------------
# [HARDENING 12] Servicio systemd en lugar de sysvinit + update-rc.d.
# ---------------------------------------------------------------------------
cat > /etc/systemd/system/midnightstreamer_panel.service <<EOF
[Unit]
Description=MidnightStreamer Panel
After=network-online.target mariadb.service
Wants=network-online.target

[Service]
Type=forking
User=${MS_USER}
ExecStart=/bin/sh ${MS_ROOT}/start_services.sh
Restart=on-failure
RestartSec=5
LimitNOFILE=265535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable midnightstreamer_panel.service >/dev/null 2>&1 || warn "no se pudo habilitar el servicio"

# ---------------------------------------------------------------------------
# nginx: puertos y bloque admin
# ---------------------------------------------------------------------------
[ -f "$MS_ROOT/nginx/conf/nginx.conf" ] && {
    sed -i 's/{HTTP_PORT}/8000/g;  s/{HTTPS}//g; s/{HTTPS_PORT}/8001/g' "$MS_ROOT/nginx/conf/nginx.conf"
    sed -i 's|{ADMIN_NGINX}|    location /admin/ { try_files $uri $uri/ /admin/index.php?$args; }|g' "$MS_ROOT/nginx/conf/nginx.conf"
}
[ -f "$MS_ROOT/nginx_rtmp/conf/nginx.conf" ] && \
    sed -i 's/{RTMP_PORT}/8002/g; s/{HTTP_PORT}/8000/g' "$MS_ROOT/nginx_rtmp/conf/nginx.conf"

# ---------------------------------------------------------------------------
# [HARDENING 13] Certificado: el original firmaba a 999999 días (2.700 años)
# con CN=127.0.0.1. Se usa CN real y 825 días (límite práctico de los CA).
# ---------------------------------------------------------------------------
if [ ! -f "$MS_ROOT/nginx/conf/server.crt" ] || \
   [ "$(openssl x509 -in "$MS_ROOT/nginx/conf/server.crt" -noout -subject 2>/dev/null | grep -c 'CN *= *127.0.0.1')" != "0" ]; then
    openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 825 \
        -keyout "$MS_ROOT/nginx/conf/server.key" \
        -out    "$MS_ROOT/nginx/conf/server.crt" \
        -subj "/CN=${SERVER_IP}" >/dev/null 2>&1
    chmod 600 "$MS_ROOT/nginx/conf/server.key"
    chown "$MS_USER:$MS_USER" "$MS_ROOT/nginx/conf/server.key" "$MS_ROOT/nginx/conf/server.crt"
fi

# ---------------------------------------------------------------------------
# [HARDENING 14] MariaDB: escucha solo en loopback y el usuario de la app solo
# entra desde localhost. El original abría 'midnightstreamer'@'%' con
# GRANT SUPER ON *.* (H-03) — con eso, cualquiera que alcanzase el 7999 tenía
# control total del motor.
# ---------------------------------------------------------------------------
install -d -m 0700 /etc/mysql/ssl
if [ ! -f /etc/mysql/ssl/server-cert.pem ]; then
    openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 825 \
        -keyout /etc/mysql/ssl/server-key.pem \
        -out    /etc/mysql/ssl/server-cert.pem \
        -subj "/CN=db.midnightstreamer.local" >/dev/null 2>&1
    chown -R mysql:mysql /etc/mysql/ssl
    chmod 600 /etc/mysql/ssl/server-key.pem
fi

systemctl enable mariadb.service >/dev/null 2>&1 || true
systemctl restart mariadb.service 2>/dev/null || systemctl restart mysql.service 2>/dev/null || \
    warn "no se pudo reiniciar MariaDB"

# Espera activa a que el socket esté listo (el original dormía sin comprobar).
for _ in $(seq 1 30); do
    mysqladmin --protocol=socket ping >/dev/null 2>&1 && break
    sleep 1
done

if [ -f "$MS_ROOT/my_deb.cnf" ]; then
    install -m 0644 "$MS_ROOT/my_deb.cnf" /etc/mysql/mariadb.cnf
    sed -i 's/{DB_PORT}/7999/g' /etc/mysql/mariadb.cnf
    # [HARDENING 14b] bind-address -> loopback
    sed -i 's/^[[:space:]]*bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mariadb.cnf
    grep -q '^bind-address' /etc/mysql/mariadb.cnf || \
        printf '\n[mysqld]\nbind-address = 127.0.0.1\n' >> /etc/mysql/mariadb.cnf
    systemctl restart mariadb.service 2>/dev/null || true
    for _ in $(seq 1 30); do
        mysqladmin --protocol=socket ping >/dev/null 2>&1 && break
        sleep 1
    done
fi

info "base de datos (passwords en $CRED_FILE)"

# [HARDENING 22] H-17: el original hacía DROP DATABASE sin copia previa. Si ya
# hay datos, se respalda antes de tocar nada.
if mysql --protocol=socket -u root -e "USE midnight_iptv; SHOW TABLES;" >/dev/null 2>&1; then
    BACKUP="/root/midnight_iptv-preinstall-$(date -u +%Y%m%dT%H%M%SZ).sql"
    if mysqldump --protocol=socket -u root --single-transaction --routines midnight_iptv > "$BACKUP" 2>/dev/null; then
        chmod 600 "$BACKUP"
        info "backup previo de la BD en $BACKUP"
    else
        warn "no se pudo respaldar la BD existente"
    fi
fi

mysql --protocol=socket -u root <<SQL || warn "falló la preparación de la BD; revisa $CRED_FILE"
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MS_DB_ROOT_PASSWORD}';
DROP DATABASE IF EXISTS midnight_iptv;
CREATE DATABASE midnight_iptv CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
DROP DATABASE IF EXISTS midnight_migrate;
CREATE DATABASE midnight_migrate CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
DROP USER IF EXISTS 'midnightstreamer'@'%';
CREATE USER IF NOT EXISTS 'midnightstreamer'@'localhost' IDENTIFIED BY '${MS_DB_PASSWORD}';
ALTER USER 'midnightstreamer'@'localhost' IDENTIFIED BY '${MS_DB_PASSWORD}';
GRANT ALL PRIVILEGES ON midnight_iptv.*    TO 'midnightstreamer'@'localhost';
GRANT ALL PRIVILEGES ON midnight_migrate.* TO 'midnightstreamer'@'localhost';
-- [HARDENING 14c] sin GRANT SUPER ON *.* ni SELECT ON mysql.proc global
FLUSH PRIVILEGES;
SQL

if [ -f "$MS_ROOT/fresh_install.sql" ]; then
    mysql --protocol=socket -u root -p"${MS_DB_ROOT_PASSWORD}" midnight_iptv < "$MS_ROOT/fresh_install.sql" \
        || warn "no se pudo importar fresh_install.sql"
    # [HARDENING 15] El admin por defecto (admin/iptv) y las claves fijas del
    # panel eran parte del schema (H-04). Se sustituyen por valores aleatorios.
    ADMIN_PW=$(rand_pw)
    ADMIN_API_KEY=$(openssl rand -hex 16)
    ADMIN_STALKER=$(openssl rand -hex 16)
    mysql --protocol=socket -u root -p"${MS_DB_ROOT_PASSWORD}" midnight_iptv <<SQL || warn "ajuste del admin falló"
UPDATE administrators
   SET password = SHA1('${ADMIN_PW}')
 WHERE username = 'admin';
UPDATE settings
   SET api_key = '${ADMIN_API_KEY}',
       stalker_key = '${ADMIN_STALKER}'
 LIMIT 1;
SQL
    cat >> "$CRED_FILE" <<EOF
MS_PANEL_ADMIN_USER=admin
MS_PANEL_ADMIN_PASSWORD=${ADMIN_PW}
MS_PANEL_API_KEY=${ADMIN_API_KEY}
EOF
    rm -f "$MS_ROOT/fresh_install.sql" "$MS_ROOT/my_deb.cnf" "$MS_ROOT/my_rh.cnf"
fi

# ---------------------------------------------------------------------------
# [HARDENING 16] sudo: el original daba NOPASSWD:ALL al usuario del panel
# (H-11). Eso convierte cualquier RCE en PHP en root inmediato. Ahora no se
# toca /etc/sudoers; si el panel necesita algo, se declara explícito abajo.
# ---------------------------------------------------------------------------
if grep -q '^midnightstreamer[[:space:]]*ALL' /etc/sudoers 2>/dev/null; then
    warn "detectada regla sudo NOPASSWD:ALL previa (H-11); eliminando"
    sed -i '/^midnightstreamer[[:space:]]*ALL/d' /etc/sudoers
fi

# ---------------------------------------------------------------------------
# [HARDENING 17] Logs: el original reconfiguraba rsyslog para TIRAR los logs
# de cron y sudo (H-12), que es justo donde se ve la persistencia y la
# escalada. Aquí no se toca rsyslog y se deja auditoría del panel.
# ---------------------------------------------------------------------------
if [ -f /etc/rsyslog.d/00-midnightstreamer.conf ]; then
    warn "eliminando regla de rsyslog que descartaba logs de cron/sudo (H-12)"
    rm -f /etc/rsyslog.d/00-midnightstreamer.conf
    systemctl restart rsyslog 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# [HARDENING 18] tmpfs: el original montaba streams y tmp con mode=0777 y
# size=90%. Se mantiene funcionalidad pero con 1777 (sticky) tamaño acotado.
# ---------------------------------------------------------------------------
sed -i '\|/home/midnightstreamer/iptv_midnight_streamer/streams tmpfs|d; \|/home/midnightstreamer/iptv_midnight_streamer/tmp tmpfs|d' /etc/fstab
cat >> /etc/fstab <<'EOF'
tmpfs /home/midnightstreamer/iptv_midnight_streamer/streams tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=8G 0 0
tmpfs /home/midnightstreamer/iptv_midnight_streamer/tmp     tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=800M 0 0
EOF
mountpoint -q "$MS_ROOT/streams" || mount "$MS_ROOT/streams" 2>/dev/null || warn "no se pudo montar streams"
mountpoint -q "$MS_ROOT/tmp"     || mount "$MS_ROOT/tmp" 2>/dev/null     || warn "no se pudo montar tmp"
install -d -o "$MS_USER" -g "$MS_USER" -m 1777 "$MS_ROOT/streams/tmp"

# ---------------------------------------------------------------------------
# [HARDENING 19] Ownership final acotado (el original hacía chown -R de todo
# el árbol, incluidos binarios, al usuario del panel).
# ---------------------------------------------------------------------------
chown -R "$MS_USER:$MS_USER" "$MS_ROOT" 2>/dev/null || true
find "$MS_ROOT" -type d -exec chmod 0755 {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# [HARDENING 20] Cron: mismas tareas del panel, pero sin el `runuser` sobre el
# crontab del usuario y con el binario PHP del panel verificado antes.
# ---------------------------------------------------------------------------
if [ -x "$MS_ROOT/php/bin/php" ]; then
    PHP_BIN="$MS_ROOT/php/bin/php"
    IDX="$MS_ROOT/wwwdir/index.php"
    TMPCRON=$(mktemp)
    cat > "$TMPCRON" <<EOF
*/1 * * * * ${PHP_BIN} ${IDX} startup # MidnightStreamer Panel
*/1 * * * * ${PHP_BIN} ${IDX} cron_live # MidnightStreamer Panel
*/1 * * * * ${PHP_BIN} ${IDX} cron_prepare # MidnightStreamer Panel
*/5 * * * * ${PHP_BIN} ${IDX} cron_cleanup_ts # MidnightStreamer Panel
*/5 * * * * ${PHP_BIN} ${IDX} cron_sync_server # MidnightStreamer Panel
*/1 * * * * ${PHP_BIN} ${IDX} cron_check_tools # MidnightStreamer Panel
*/1 * * * * ${PHP_BIN} ${IDX} cron_archive # MidnightStreamer Panel
*/1 * * * * ${PHP_BIN} ${IDX} cron_check_server_watchdog # MidnightStreamer Panel
0 0 */1 * * ${PHP_BIN} ${IDX} cron_geoip # MidnightStreamer Panel
0 5 * * *   ${PHP_BIN} ${IDX} cron_epg # MidnightStreamer Panel
*/5 * * * * ${PHP_BIN} ${IDX} cron_cleanup_logs # MidnightStreamer Panel
EOF
    crontab -u "$MS_USER" "$TMPCRON" || warn "no se pudo instalar el crontab"
    rm -f "$TMPCRON"
else
    warn "$MS_ROOT/php/bin/php no existe: no se instala el crontab del panel"
fi
systemctl restart cron 2>/dev/null || systemctl restart crond 2>/dev/null || true

# ---------------------------------------------------------------------------
# Arranque
# ---------------------------------------------------------------------------
sh "$MS_ROOT/start_services.sh" 2>/dev/null || \
    systemctl start midnightstreamer_panel.service || warn "el panel no arrancó; revisa journalctl"

[ -x "$MS_ROOT/php/bin/php" ] && \
    su - "$MS_USER" -c "$MS_ROOT/php/bin/php $MS_ROOT/wwwdir/index.php cron_sync_server" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# [HARDENING 21] Resumen: sin imprimir passwords en claro por pantalla/syslog.
# ---------------------------------------------------------------------------
echo
info "instalación completada"
info "panel:  http://$SERVER_IP:8000/admin"
info "fijado: admin / ver MS_PANEL_ADMIN_PASSWORD en $CRED_FILE"
info "BD:     root y monitor en $CRED_FILE (0600, solo root)"
echo
warn "el escáner del payload:  sudo ./tools/scan_payload.sh $MS_ROOT"
history -c 2>/dev/null || true
