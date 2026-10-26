#!/usr/bin/env bash
# P15 (S2-34): la API (usuario 10002) no puede leer la clave privada del firmante (usuario 10001).
#
# Usa volúmenes con nombre dentro del motor de Docker, no carpetas montadas desde Windows o macOS, para que
# los dueños y los permisos sean los reales de Linux. La clave es efímera y se borra al terminar.
#
# Uso: bash apps/signer/scripts/p15-isolation.sh [imagen]     (por defecto alertasegura-signer:moto)
# Construir antes:  docker build -f infra/docker/signer.Dockerfile -t alertasegura-signer:moto .
set -u
IMAGE="${1:-alertasegura-signer:moto}"
SUFFIX="$$"
KEYS="p15-keys-$SUFFIX"
RUN="p15-run-$SUFFIX"
NAME="p15-signer-$SUFFIX"
FAILED=0

# MSYS_NO_PATHCONV evita que Git Bash en Windows convierta las rutas /run/... en rutas de Windows.
export MSYS_NO_PATHCONV=1

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILED=1; }

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1
  docker volume rm "$KEYS" "$RUN" >/dev/null 2>&1
}
trap cleanup EXIT

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "No existe la imagen $IMAGE: constrúyela primero."; exit 2; }
docker volume create "$KEYS" >/dev/null && docker volume create "$RUN" >/dev/null

# 1. Se genera una clave efímera DENTRO del volumen, con dueño 10001 y modo 0400 (como en producción).
docker run --rm --user 0:0 --entrypoint node -v "$KEYS:/run/secrets" "$IMAGE" -e "
const { generateKeyPairSync } = require('node:crypto');
const fs = require('node:fs');
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
fs.writeFileSync('/run/secrets/signer-private-key.pem', privateKey.export({ type: 'pkcs8', format: 'pem' }));
fs.chownSync('/run/secrets/signer-private-key.pem', 10001, 10001);
fs.chmodSync('/run/secrets/signer-private-key.pem', 0o400);
" || { echo "No se pudo preparar la clave de prueba"; exit 2; }

# 2. El firmante arranca como 10001 con la clave de solo lectura y el sistema de archivos de solo lectura.
docker run -d --name "$NAME" --user 10001:10001 --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -e SIGNER_PRIVATE_KEY_PATH=/run/secrets/signer-private-key.pem \
  -v "$KEYS:/run/secrets:ro" -v "$RUN:/run/signer" "$IMAGE" >/dev/null || { echo "No arrancó el firmante"; exit 2; }

for _ in $(seq 1 20); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null)" = "healthy" ] && break
  sleep 1
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null)" = "healthy" ] \
  && pass "el firmante (uid 10001) arranca con la clave y responde /health" \
  || fail "el firmante no llegó a estado healthy"

# 3. Dueño y modo de la clave y del socket vistos desde el firmante.
KEY_STAT="$(docker exec "$NAME" stat -c '%u:%g %a' /run/secrets/signer-private-key.pem)"
[ "$KEY_STAT" = "10001:10001 400" ] && pass "la clave es 10001:10001 con modo 0400 ($KEY_STAT)" || fail "permisos de la clave inesperados: $KEY_STAT"
SOCK_STAT="$(docker exec "$NAME" stat -c '%u:%g %a' /run/signer/signer.sock)"
[ "$SOCK_STAT" = "10001:10001 660" ] && pass "el socket es 10001:10001 con modo 0660 ($SOCK_STAT)" || fail "permisos del socket inesperados: $SOCK_STAT"

# 4. La API (10002), ni siquiera con el grupo 10001, puede leer la clave.
for extra in "" "--group-add 10001"; do
  label="${extra:-sin grupo}"
  # shellcheck disable=SC2086
  OUT="$(docker run --rm --user 10002:10002 $extra --entrypoint cat -v "$KEYS:/run/secrets:ro" "$IMAGE" /run/secrets/signer-private-key.pem 2>&1)"
  if echo "$OUT" | grep -q "Permission denied" && ! echo "$OUT" | grep -q "PRIVATE KEY"; then
    pass "10002 ($label) no puede leer la clave: Permission denied"
  else
    fail "10002 ($label) pudo leer la clave o falló por otra causa: $OUT"
  fi
done

# 5. Sin el grupo 10001 la API tampoco llega al socket; con el grupo sí (es lo que debe declarar el compose).
SOCKET_CALL="require('http').get({socketPath:'/run/signer/signer.sock',path:'/health'},r=>process.exit(r.statusCode===200?0:3)).on('error',e=>{console.error(e.code);process.exit(4)})"
OUT="$(docker run --rm --user 10002:10002 --entrypoint node -v "$RUN:/run/signer" "$IMAGE" -e "$SOCKET_CALL" 2>&1)"
[ "$?" -ne 0 ] && echo "$OUT" | grep -q "EACCES" \
  && pass "10002 sin grupo no puede conectarse al socket: EACCES" \
  || fail "10002 sin grupo debería recibir EACCES al socket: $OUT"
docker run --rm --user 10002:10002 --group-add 10001 --entrypoint node -v "$RUN:/run/signer" "$IMAGE" -e "$SOCKET_CALL" >/dev/null 2>&1 \
  && pass "10002 con group_add 10001 sí llega al socket (/health 200)" \
  || fail "10002 con group_add 10001 no llegó al socket"

# 6. La imagen no contiene ninguna clave privada.
FOUND="$(docker run --rm --entrypoint sh "$IMAGE" -c "grep -rl 'BEGIN .*PRIVATE KEY' /app /etc /home 2>/dev/null | head -3")"
[ -z "$FOUND" ] && pass "la imagen no contiene claves privadas" || fail "la imagen contiene claves privadas: $FOUND"

echo
[ "$FAILED" -eq 0 ] && echo "P15: APROBADA" || echo "P15: FALLIDA"
exit "$FAILED"
