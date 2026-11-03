# Cómo completar la auditoría del payload

El instalador ya está auditado y parcheado. Lo que falta es el panel en sí
(`ms_install_5.2.8.tar.gz`), que en el entorno de auditoría no se pudo descargar.

## 1 · Consigue el payload (tú, no el script)

Descárgalo en una máquina tuya, **no** en el servidor de producción:

```bash
# calcula el hash tú mismo; no confíes en uno copiado de un chat o un foro
curl -fL -o ms_install_5.2.8.tar.gz https://valut.iptvtools.io/MidnightStreamer/ms_install_5.2.8.tar.gz
sha256sum ms_install_5.2.8.tar.gz
```

## 2 · Extráelo sin instalar nada

```bash
mkdir -p /tmp/mds-payload
tar -xzf ms_install_5.2.8.tar.gz -C /tmp/mds-payload
# si el tar tiene un directorio raíz, entra en él:
find /tmp/mds-payload -maxdepth 2 -name cms -o -maxdepth 2 -name wwwdir
```

## 3 · Escanéalo

```bash
./tools/scan_payload.sh /tmp/mds-payload
# informe estructurado:
./tools/scan_payload.sh /tmp/mds-payload --json > reporte.json
```

El escáner devuelve **exit 1** si hay algo crítico. No instales sin revisar `C-01`, `C-02`,
`C-06`, `C-09`, `C-15` y `C-18`.

## 4 · Lo que el escáner no puede decidir por ti

| Señal | Qué hacer |
|---|---|
| `C-09` dominios de licencia | Sigue el flujo en el PHP: quién llama, con qué datos y si envía el contenido de `config` |
| `C-16` cadenas en binarios | Compara `php`, `ffmpeg` y `ffprobe` con builds oficiales; si no coinciden, no los uses |
| `C-20` blob `config`/`license` | Mira qué los descifra y adónde va el resultado |
| `C-08` llamadas salientes | Lista los destinos y qué se envía en cada una |

## 5 · Instala con la versión endurecida

```bash
sudo MS_PAYLOAD_SHA256=$(sha256sum ms_install_5.2.8.tar.gz | cut -d' ' -f1) \
     ./installer/ms_install_offline.sh
```

Credenciales generadas: `/root/.midnightstreamer.credentials` (0600). No se imprime ninguna por pantalla.
