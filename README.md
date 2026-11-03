# bvrt-streamer

Fork de auditoría y endurecimiento de **MidnightStreamer** (`MDS-Unofficial/MidnightStreamer`).

> El objetivo no es reescribir el panel, es **dejar constancia comprobable** de qué hace el instalador
> de serie, qué está roto o es peligroso, y una versión corregida que puedas comparar línea a línea.
> El original se conserva **intacto** en `upstream/` para que cada afirmación sea verificable.

---

## Estado

| | |
|---|---|
| Payload `ms_install_5.2.8.tar.gz` | ❌ **no descargado** — `valut.iptvtools.io` (BunnyCDN) inalcanzable desde el entorno de auditoría |
| Instalador `ms_install_offline.sh` | ✅ auditado (SHA256 `57af018e…65885`) y parcheado |
| CMS / PHP del panel | ⏳ pendiente del payload — cubierto por `tools/scan_payload.sh` |
| Hallazgos | 5 críticos · 7 altos · 5 medios |

Informe completo: **[`docs/auditoria.html`](docs/auditoria.html)** (versión navegable) ·
**[`docs/HALLAZGOS.md`](docs/HALLAZGOS.md)** (Markdown con el código citado).

---

## Contenido

```
upstream/         copia sin modificar del instalador auditado (+ Players/README.txt)
installer/        instalador endurecido: 22 bloques [HARDENING n] ligados a su hallazgo
tools/            scan_payload.sh — 20 comprobaciones estáticas sobre el .tar.gz extraído
docs/             auditoria.html · HALLAZGOS.md · INSTALAR-EN-VPS.md · ACCESO-SEGURO.md
tests/            pruebas del escáner contra un payload de muestra
```

## Uso

### Instalar en un servidor (guía completa: [`docs/INSTALAR-EN-VPS.md`](docs/INSTALAR-EN-VPS.md))

```bash
# 1) payload del panel (lo descargas tú y calculas su hash)
curl -fL -o ms_install_5.2.8.tar.gz https://valut.iptvtools.io/MidnightStreamer/ms_install_5.2.8.tar.gz
export MS_PAYLOAD_SHA256=$(sha256sum ms_install_5.2.8.tar.gz | awk '{print $1}')

# 2) bootstrap: descarga a archivo, verifica sha256, pide confirmación y ejecuta
curl -fsSL -O https://raw.githubusercontent.com/TalaveraSama/bvrt-streamer/main/install.sh
curl -fsSL -O https://raw.githubusercontent.com/TalaveraSama/bvrt-streamer/main/install.sh.sha256
sha256sum -c install.sh.sha256          # si falla, NO ejecutes

sudo MS_PAYLOAD_SHA256="$MS_PAYLOAD_SHA256" bash install.sh
```

`install.sh` **no** es `curl | bash`: descarga el instalador a un archivo, lo verifica contra
`installer/ms_install_offline.sh.sha256`, te enseña el resumen, pide escribir `instalar` y solo
entonces lo ejecuta.

### Auditar el VPS después de instalar

```bash
bash tools/vps_audit.sh --out /root/audit-postinstall.txt   # solo lectura
```

### Auditar un payload antes de instalarlo

```bash
tar -xzf ms_install_5.2.8.tar.gz -C /tmp/mds-payload
./tools/scan_payload.sh /tmp/mds-payload
```

Sale con código 1 si hay hallazgos críticos, así que encaja en CI. Modos: `--json` para reporte
estructurado, `--strict` para fallar también con medios.

### Instalar con la versión endurecida

```bash
sha256sum ms_install_5.2.8.tar.gz          # calcula tú el hash, no lo copies de ningún sitio
sudo MS_PAYLOAD_SHA256=<hash> ./installer/ms_install_offline.sh
```

Variables soportadas:

| Variable | Por defecto | Para qué |
|---|---|---|
| `MS_PAYLOAD_SHA256` | **obligatoria** | integridad del tar.gz |
| `MS_PAYLOAD` | autodetecta | ruta al tar.gz |
| `MS_DB_PASSWORD` | aleatoria | password del usuario de BD |
| `MS_DB_ROOT_PASSWORD` | aleatoria | password root de MariaDB |
| `MS_SKIP_NVIDIA` | `1` | `0` instala los drivers del payload (sin verificar) |
| `MS_SELINUX_RELABEL` | `0` | `1` aplica contexto SELinux en vez de desactivarlo |

Las credenciales generadas quedan en **`/root/.midnightstreamer.credentials`** (0600).

### Verificar cada cambio

```bash
diff -u upstream/ms_install_offline.sh installer/ms_install_offline.sh
```

---

## Los cinco críticos, en una línea cada uno

1. **H-03** — MariaDB con `'midnightstreamer'@'%'` y `GRANT SUPER ON *.*`, password `pglauD4F0L` igual en todo el mundo.
2. **H-04** — admin/iptv por defecto; `api_key` y `stalker_key` publicados en el script.
3. **H-11** — `NOPASSWD:ALL` en `/etc/sudoers` para el usuario del panel: un RCE en PHP = root.
4. **H-06** — repos APT `[trusted=yes]` (sin GPG) de Debian jessie / Ubuntu trusty (EOL) por HTTP, y no se borran nunca.
5. **H-07** — SELinux desactivado de forma permanente sin motivo funcional.

Y el que más «huele»: **H-12**, el instalador reconfigura rsyslog para **tirar los logs de `cron` y `sudo`**,
que son justo los dos que sirven para detectar persistencia y escalada.

---

## Aviso

Esto es una auditoría de seguridad de código ajeno a partir de su instalador público, no un producto
certificado. Si vas a poner el panel en producción, instálalo en un servidor aislado, con el payload
escaneado, y cambia **todas** las credenciales antes de exponerlo a internet.
