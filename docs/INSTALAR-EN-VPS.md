# Instalar en el VPS desde GitHub

Guía para ejecutarlo **tú**, sin darme acceso al servidor. Todo sale de este repo.

> **Antes de empezar:** esto instala un panel de terceros con root en una máquina tuya.
> Hazlo en un servidor limpio (Ubuntu 22.04/24.04 recomendado) y **no** en uno que ya esté
> en producción con el panel viejo. Si el viejo está comprometido, reinstala desde cero.

---

## 0 · Requisitos

| | |
|---|---|
| SO | Ubuntu 20/22/24 o Debian 11/12, x86_64, limpio |
| Acceso | root (o sudo) |
| RAM | 4 GB mínimo para el panel + MariaDB |
| Disco | 20 GB (el payload + tmpfs de streams) |

```bash
# comprueba que estás en un servidor limpio
free -h && df -h / && cat /etc/os-release | head -2
```

---

## 1 · Descarga el payload del panel (tú, en el VPS)

```bash
cd /root
curl -fL --retry 3 -o ms_install_5.2.8.tar.gz \
  https://valut.iptvtools.io/MidnightStreamer/ms_install_5.2.8.tar.gz

# calcula el hash TÚ MISMO (no lo copies de ningún chat ni de este documento)
sha256sum ms_install_5.2.8.tar.gz
```

Apunta el hash. Es lo que garantiza que no cambió nada entre la descarga y la instalación:

```bash
export MS_PAYLOAD_SHA256=$(sha256sum /root/ms_install_5.2.8.tar.gz | awk '{print $1}')
echo "$MS_PAYLOAD_SHA256"
```

---

## 2 · Escanéalo ANTES de instalar (recomendado)

```bash
cd /root
curl -fsSL -O https://raw.githubusercontent.com/TalaveraSama/bvrt-streamer/main/tools/scan_payload.sh

mkdir -p /root/ms-payload
tar -xzf ms_install_5.2.8.tar.gz -C /root/ms-payload
bash scan_payload.sh /root/ms-payload
```

Si sale **exit 1**, hay hallazgos críticos: no instales hasta revisarlos. Si sale limpio, sigue.
Esto es lo único que puede decirte qué hay dentro del CMS, porque yo no pude descargarlo.

---

## 3 · Descarga y verifica el instalador

```bash
cd /root
curl -fsSL -O https://raw.githubusercontent.com/TalaveraSama/bvrt-streamer/main/install.sh
curl -fsSL -O https://raw.githubusercontent.com/TalaveraSama/bvrt-streamer/main/install.sh.sha256

# verificación: si esto falla, NO ejecutes nada
sha256sum -c install.sh.sha256
```

El `install.sh` a su vez:

1. descarga `installer/ms_install_offline.sh` **a un archivo**, nunca a un pipe;
2. lo verifica contra `installer/ms_install_offline.sh.sha256` del repo;
3. te enseña el resumen y te pide escribir `instalar`;
4. solo entonces lo ejecuta.

Puedes leerlo entero antes: son ~190 líneas de bash.

---

## 4 · Instala

```bash
cd /root
sudo MS_PAYLOAD_SHA256="$MS_PAYLOAD_SHA256" \
     MS_PAYLOAD=/root/ms_install_5.2.8.tar.gz \
     bash install.sh
```

Al terminar:

```bash
cat /root/.midnightstreamer.credentials     # 0600, solo root
```

Ahí están la password de root de MariaDB, la del usuario de la BD y la del panel.
**Guárdalas en un gestor y borra ese archivo** cuando las tengas.

Panel: `http://<tu-ip>:8000/admin`

---

## 5 · Verifica lo que se instaló

```bash
cd /root
curl -fsSL -O https://raw.githubusercontent.com/TalaveraSama/bvrt-streamer/main/tools/vps_audit.sh
bash vps_audit.sh --out /root/audit-postinstall.txt
```

Mira estas cinco líneas del informe:

| Sección | Esperado | Si no |
|---|---|---|
| 6 · MySQL | solo `@'localhost'`, sin `@'%'` | algo falló en `[HARDENING 14]` |
| 6 · root | **no** entra con `iptv` ni sin password | cambia la password ya |
| 1 · sudo | ninguna línea `NOPASSWD` de `midnightstreamer` | revisa `/etc/sudoers` |
| 3 · rsyslog | `00-midnightstreamer.conf` **ausente** | se restauró el que tiraba logs |
| 4 · rootkits | `/etc/ld.so.preload` vacío | posible compromiso previo |

Y comprueba lo básico por fuera:

```bash
# desde otra máquina — 7999 y 3306 NO deben ser accesibles desde fuera
nmap -Pn -p 22,3306,7999,8000,8001 <tu-ip>
```

`3306` y `7999` tienen que salir **closed/filtered**. Si salen abiertos, el `bind-address`
no se aplicó: para el panel y arréglalo antes de seguir.

---

## 6 · Diferencias con el instalador oficial

Si algo no funciona y quieres comparar con el original:

```bash
cd /root
curl -fsSL -o original.sh https://raw.githubusercontent.com/TalaveraSama/bvrt-streamer/main/upstream/ms_install_offline.sh
curl -fsSL -o hardened.sh https://raw.githubusercontent.com/TalaveraSama/bvrt-streamer/main/installer/ms_install_offline.sh
diff -u original.sh hardened.sh | less
```

Los 22 bloques `[HARDENING n]` van etiquetados y cada uno referencia su hallazgo (`H-01`…`H-17`)
documentado en `docs/HALLAZGOS.md`.

---

## Si falla

| Síntoma | Causa habitual |
|---|---|
| `die "ya existe una instalación"` | ya hay un panel: bórralo a mano o usa otro servidor |
| falla `apt-get` | el repo del payload usa paquetes EOL; mira el log y adapta |
| el panel no arranca | `journalctl -u midnightstreamer_panel -n 50` |
| MariaDB no arranca | `bind-address` + `my_deb.cnf`; revisa `/var/log/mysql/error.log` |
| `MS_PAYLOAD_SHA256` inválida | mayúsculas/minúsculas dan igual, pero el hash debe ser el del archivo exacto |

### Volver atrás

El instalador **no** guarda rollback automático. Antes de empezar, si el servidor tiene algo
que te importe:

```bash
tar -czf /root/preinstall-backup.tar.gz \
    /etc/sudoers /etc/fstab /etc/sysctl.conf /etc/mysql /etc/apt/sources.list.d 2>/dev/null
mysqldump --all-databases > /root/preinstall-db.sql 2>/dev/null
```

Si tienes snapshot del proveedor, tómalo. Es lo único que te devuelve el servidor idéntico.
