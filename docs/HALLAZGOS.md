# Hallazgos de seguridad — MidnightStreamer `ms_install_offline.sh`

**Objetivo auditado:** `MDS-Unofficial/MidnightStreamer` → `ms_install_offline.sh`
**SHA256:** `57af018eb6cf4b189eae124ed4fa7953c82da26801775f100eb8f624f2965885` (32 047 bytes, 525 líneas)
**Copia sin modificar:** [`upstream/ms_install_offline.sh`](../upstream/ms_install_offline.sh)
**Versión parcheada:** [`installer/ms_install_offline.sh`](../installer/ms_install_offline.sh)
**Fecha:** 2026-11-03

---

## Resumen

| Severidad | Nº | Qué significa en la práctica |
|---|---|---|
| Crítico | 5 | Credenciales fijas en todas las instalaciones, sudo a root sin password, repos sin firma por HTTP, desactivación de SELinux |
| Alto | 7 | Borrado ciego del home, kill de procesos ajenos, drivers sin verificar, apagado de logs de cron/sudo, MySQL expuesto |
| Medio | 4 | Certificados a 2 700 años, tmpfs 0777, `rm -rf` sobre rutas variables, blobs de config compartidos |

> **El instalador no es un troyano obvio: no descarga nada y no contiene `curl | bash`.**
> Pero deja el servidor en un estado equivalente a comprometido si alguien alcanza el puerto 7999 o
> consigue una ejecución de PHP, porque regala root y credenciales conocidas.

---

## Crítico

### H-03 · Usuario de MariaDB accesible desde cualquier host con `SUPER`
`ms_install_offline.sh:453-462`

```sql
GRANT ALL PRIVILEGES ON midnight_iptv.*    TO 'midnightstreamer'@'%' IDENTIFIED BY 'pglauD4F0L';
GRANT SUPER ON *.*                         TO 'midnightstreamer'@'%' IDENTIFIED BY 'pglauD4F0L';
```

- La contraseña `pglauD4F0L` es **la misma en todas las instalaciones del mundo** y está publicada en este repo.
- `@'%'` + `GRANT SUPER ON *.*` significa: quien alcance el puerto 7999 entra como superusuario y puede
  leer/escribir cualquier base, crear usuarios, o usar `SELECT ... INTO OUTFILE` para escribir archivos
  como el usuario `mysql`.
- Combinado con `fresh_install.sql` dentro del payload, esto es una puerta abierta permanente.

**Mitigación:** `bind-address = 127.0.0.1`, usuario solo `@'localhost'`, sin `SUPER`, password aleatoria.
→ `[HARDENING 14]`

### H-04 · Administrador y claves del panel hardcodeados
`ms_install_offline.sh:451-452`

```sql
INSERT INTO administrators (username, password, ...) VALUES ('admin', '2cd71063c6a79832cdfeb889f4c072e425067fe2', ...);
UPDATE settings SET preview_pass = 'hn6SImdyx7', stalker_key = '02230129b6ad71bae0292032450090cd', api_key = 'dtqVa5xwoU';
```

- `admin` / `iptv` en todas las instalaciones (lo confirma el propio script al final, línea 524).
- `stalker_key` y `api_key` públicos: cualquiera puede emitir peticiones firmadas a cualquier panel que
  no los haya cambiado.
- `preview_pass` fijo: acceso a la vista previa sin credenciales.

**Mitigación:** password aleatoria + `api_key`/`stalker_key` aleatorios, guardados en `/root/.midnightstreamer.credentials` a 0600.
→ `[HARDENING 15]`

### H-11 · `NOPASSWD:ALL` para el usuario del panel
`ms_install_offline.sh:335-337`

```bash
grep -v "midnightstreamer" /etc/sudoers > /tmp/sudoers.tmp && mv /tmp/sudoers.tmp /etc/sudoers
echo "midnightstreamer ALL = (ALL) NOPASSWD:ALL" >> /etc/sudoers
```

Cualquier RCE en el PHP del panel (que además corre con ese usuario) pasa a **root sin contraseña**.
Es la diferencia entre "me tumbaron el panel" y "me tomaron el servidor".

**Mitigación:** no se toca `/etc/sudoers`; se elimina la regla si ya existe.
→ `[HARDENING 16]`

### H-06 · Repositorios APT sin firma, EOL y por HTTP
`ms_install_offline.sh:216-232`

```bash
echo "deb [trusted=yes] http://httpredir.debian.org/debian jessie ..." > /etc/apt/sources.list.d/midnightstreamer.list
echo "deb [trusted=yes] http://de.archive.ubuntu.com/ubuntu/ trusty ..." >> ...
```

- `[trusted=yes]` = **sin verificación GPG**: cualquier cosa que responda a esa URL se instala como root.
- `jessie` (Debian 8, EOL 2020) y `trusty` (Ubuntu 14.04, EOL 2019): paquetes con CVEs conocidos.
- Todo por HTTP: MITM trivial en cualquier red intermedia.
- Y no se elimina nunca, así que queda activo para el futuro `apt-get install` del administrador.

**Mitigación:** se borra ese archivo y se usan solo los repos del sistema.
→ `[HARDENING 6]`

### H-07 · SELinux desactivado
`ms_install_offline.sh:124-125`

```bash
setenforce 0
sed -i 's/enforcing/disabled/g' /etc/selinux/config
```

Desactiva permanentemente la única capa de contención del sistema para el panel y para todo lo demás.
Ninguna razón funcional lo justifica: si hiciera falta, se habría resuelto con contextos (`semanage`/`restorecon`).

**Mitigación:** no se desactiva; se ofrece `MS_SELINUX_RELABEL=1`.
→ `[HARDENING 5]`

---

## Alto

### H-01 · `rm -rf *` sobre el home, sin comprobaciones
`ms_install_offline.sh:57-61`

```bash
cd /home/midnightstreamer
if [ "$PWD" = "/home/midnightstreamer" ]; then
    rm -rf *
```

Si el usuario ya existe con datos (backups, `.ssh`, volúmenes), **se borra todo**. El `if` solo comprueba
el `$PWD`, no que el contenido sea del panel. Un `cd` fallido en otra versión del script deja el `rm -rf *`
apuntando al directorio actual del operador.

**Mitigación:** se borra solo `$MS_ROOT` con `find -mindepth 1 -maxdepth 1 -exec rm -rf`. → `[HARDENING 4]`

### H-02 · `pkill -9` indiscriminado
`ms_install_offline.sh:27-29`

```bash
pkill -9 php
pkill -9 ffmpeg
```

Mata **cualquier** PHP/ffmpeg del servidor, incluidos otros paneles, colas de transcodificación o tareas
en curso. Puede corromper grabaciones y dejar el sistema en estado inconsistente.

**Mitigación:** `pkill -TERM -x` solo de los tres procesos del panel. → `[HARDENING 3]`

### H-12 · Se tiran los logs de `cron` y `sudo`
`ms_install_offline.sh:468-476`

```
cron.*          stop
:syslogtag, startswith, "CRON" stop
:syslogtag, startswith, "sudo" stop
```

Este es el hallazgo con más "olor" a ocultación: `sudo` y `cron` son exactamente las dos fuentes que usas
para detectar escalada de privilegios y persistencia. Un panel legítimo **quiere** esos logs.
No hay ningún motivo operativo para silenciarlos; solo reduce la detectabilidad de un atacante
(y de paso la tuya, cuando auditas tu propio servidor).

**Mitigación:** no se toca rsyslog y se elimina la regla si existe. → `[HARDENING 17]`

### H-08 · Drivers NVIDIA del payload, sin verificar y con blacklist permanente
`ms_install_offline.sh:361-370` (Debian) y `387-394` (RHEL)

```bash
apt-get purge nvidia-* -y
echo "blacklist nouveau" >> /etc/modprobe.d/nvidia-installer-disable-nouveau.conf
nvidia-uninstall --silent
sh /home/midnightstreamer/iptv_midnight_streamer/NVIDIA-Linux-x86_64-570.144.run --silent --install-libglvnd
```

Un `.run` de 300+ MB que viaja dentro del `.tar.gz`, **sin checksum ni firma**, ejecutado como root, y que
purga los drivers del sistema antes. Si el payload está manipulado, esto es ejecución de código root
inmediata en el momento de instalar. Además deja `nouveau` en blacklist para siempre.

**Mitigación:** desactivado por defecto (`MS_SKIP_NVIDIA=1`); si se necesita, es decisión explícita.
→ `[HARDENING 7]`

### H-13 · Certificados a 999 999 días con CN fijo
`ms_install_offline.sh:333`, `433`

```bash
openssl req -x509 ... -subj "/CN=127.0.0.1" -days 999999
```

- 2 738 años de validez: si la clave se filtra (y está en el árbol del panel), es válida para siempre.
- `CN=127.0.0.1` en el certificado de nginx: ningún cliente lo va a validar, así que en la práctica
  todo el mundo acaba desactivando la verificación TLS del panel.
- La clave privada de MySQL queda en `chmod -R 755` (H-15).

**Mitigación:** CN real, 825 días, clave a 0600. → `[HARDENING 13]`

### H-15 · Clave privada de MySQL legible por todos
`ms_install_offline.sh:436`

```bash
chmod -R 755 /etc/mysql/ssl/
```

`755` sobre `server-key.pem` deja la clave privada del servidor de BD legible por cualquier usuario local.

**Mitigación:** `700` en el directorio y `600` en la clave. → `[HARDENING 14]`

### H-16 · tmpfs `mode=0777` al 90 % del disco
`ms_install_offline.sh:341-342`

```bash
echo "tmpfs ...streams tmpfs defaults,...,mode=0777,size=90% 0 0" >> /etc/fstab
```

Escritura libre para cualquier usuario del sistema en un directorio que además está dentro del docroot del
panel. Un usuario sin privilegios puede llenar el 90 % de la RAM (DoS) o plantar un archivo que el panel
sirva.

**Mitigación:** `mode=1777` (sticky) y tamaño acotado. → `[HARDENING 18]`

---

## Medio

### H-05 · Payload sin verificación de integridad
`ms_install_offline.sh:67-69`

```bash
cp $current_dir/ms_install_5.9.1.tar.gz /home/midnightstreamer/ms_install.tar.gz
tar -xvzf ms_install.tar.gz
```

- Nombre de versión **fijo** (`5.9.1`) mientras el enlace que circula es `5.2.8`: instalas lo que haya,
  no lo que crees.
- Sin `sha256sum` ni firma: un `.tar.gz` sustituido en el CDN se instala tal cual como root.
- `$current_dir` sin comillas además rompe con rutas que tengan espacios.

**Mitigación:** `MS_PAYLOAD_SHA256` obligatoria. → `[HARDENING 1]`

### H-09 · Blobs `config` / `license` cifrados e idénticos en todas las instalaciones
`ms_install_offline.sh:84-85` (y reinyectados en `syncs`, línea 450)

```bash
echo "f40ed93c8db9...ZyZWxeZ4ht5r3a..." > .../config
echo "ivyrIv6Id063SS9Hcwlet3ClDPz4l9Vgg..." > .../license
```

- Son **constantes globales**: no se generan por instalación. Cualquiera con el panel tiene el blob de
  licencia de todos los demás.
- Son el canal natural del callback de licencia/telemetría. Sin el código PHP no se puede afirmar
  qué contienen, pero **esto es exactamente donde hay que mirar** cuando audites el payload.
- Nota importante: no se puede descifrar sin la clave (que va en el PHP compilado), así que
  aquí no hay conclusión, hay una **prioridad de revisión**.

**Mitigación:** no se escriben; se usa el alta de licencia del panel. El escáner marca el archivo. → `[HARDENING 9]` + `C-20`

### H-10 · Binarios precompilados sin cadena de confianza
`php/`, `bin/ffmpeg`, `bin/ffprobe`, `libzip5-*.rpm`

PHP 8.3.36 y 7.4.34, ffmpeg/ffprobe y un RPM viajan dentro del payload. Sin checksums publicados,
sin firma, sin build reproducible. El instalador incluso enlaza `libzip.so.5 → libzip.so.4` para forzar
compatibilidad, lo que indica binarios construidos contra otra distro.

**Mitigación:** el escáner hace `strings` sobre los binarios buscando endpoints y dominios (`C-16`).
→ `tools/scan_payload.sh`

### H-14 · `rm -rf` y `mv` sobre rutas no comprobadas
`ms_install_offline.sh:78-96`, `113-121`

Los bloques PHP/`wwwdir` hacen `rm -rf` y `mv` sobre rutas absolutas asumiendo que existen. Si el payload es
de otra versión (ver H-05), quedan directorios a medias y el `mv` puede mover algo que no toca.

**Mitigación:** comprobaciones `[ -d ]` antes de cada `mv`. → `[HARDENING 8]`

### H-17 · Base de datos borrada sin condición
`ms_install_offline.sh:444`

```sql
DROP DATABASE IF EXISTS midnight_iptv; CREATE DATABASE midnight_iptv ...
```

Reinstalar el panel **destruye la base sin preguntar ni hacer copia**. En un servidor de producción esto
es pérdida de datos garantizada en el primer reintento de instalación.

**Mitigación:** se aborta si ya hay instalación (`[HARDENING 0]`) y se hace `mysqldump` previo antes del
`DROP` cuando existe la base.

---

## Lo que este informe NO puede decir

Sin el payload (`ms_install_5.2.8.tar.gz`) **no** es posible afirmar si el panel contiene:

- webshells o backdoors en el PHP del CMS,
- el destino real del callback de licencia,
- qué hacen los binarios precompilados,
- si `wwwdir/index.php` ejecuta código remoto.

Esa parte la cubre `tools/scan_payload.sh` en cuanto tengas el `.tar.gz`. Los dominios de descarga
(`valut.iptvtools.io`, `iptvtools.b-cdn.net`) **no son accesibles desde este entorno**, por lo que el
payload no pudo obtenerse aquí.
