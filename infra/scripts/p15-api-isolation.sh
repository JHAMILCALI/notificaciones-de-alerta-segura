#!/usr/bin/env bash
# P15 (S2-34), parte de la API: el contenedor `api` (usuario 10002) no puede leer la clave privada del firmante
# (usuario 10001). Complementa a apps/signer/scripts/p15-isolation.sh, que prueba el lado del firmante.
#
# Tres comprobaciones:
#   A. En el contenedor api del perfil g2 la clave NO está montada: leerla da ENOENT.
#   B. Aunque la clave estuviera montada en la misma ruta con dueño 10001 y modo 0400, la API (10002, que además
#      pertenece al grupo 10001 para entrar al socket) recibe EACCES. Se prueba con un volumen con nombre para que
#      el dueño y el modo sean los reales de Linux (no los de una carpeta de Windows montada).
#   C. Control: el usuario 10001 SÍ lee esa misma clave (así B no es una prueba vacua).
#
# Uso: bash infra/scripts/p15-api-isolation.sh [contenedor-api]
#      (sin argumento solo se ejecutan B y C con la imagen indicada en API_IMAGE; con argumento también A)
#      API_IMAGE=<imagen>  imagen de la API (por defecto, la del contenedor indicado)
set -u
CONTAINER="${1:-}"
FAILED=0
export MSYS_NO_PATHCONV=1 # Git Bash en Windows no debe convertir las rutas /run/... en rutas de Windows

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILED=1; }

if [ -n "$CONTAINER" ]; then
  IMAGE="${API_IMAGE:-$(docker inspect -f '{{.Config.Image}}' "$CONTAINER" 2>/dev/null)}"
else
  IMAGE="${API_IMAGE:-}"
fi
[ -n "$IMAGE" ] || { echo "Indique el contenedor api o API_IMAGE=<imagen>."; exit 2; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "No existe la imagen $IMAGE."; exit 2; }

READ_JS="try{require('fs').readFileSync('/run/secrets/signer-private-key.pem');console.log('LEIDA')}catch(e){console.log(e.code)}"

echo "P15 — aislamiento de la clave privada del firmante respecto de la API"
echo "fecha=$(date -u +%Y-%m-%dT%H:%M:%SZ) imagen=$IMAGE ${CONTAINER:+contenedor=$CONTAINER}"
echo

# A. El contenedor api en ejecución.
if [ -n "$CONTAINER" ]; then
  UID_API="$(docker exec "$CONTAINER" id -u)"
  GROUPS_API="$(docker exec "$CONTAINER" id -G)"
  [ "$UID_API" = "10002" ] && pass "A1. el contenedor api corre como el usuario $UID_API (grupos: $GROUPS_API)" \
    || fail "A1. el contenedor api no corre como 10002 (uid=$UID_API)"
  MOUNTS="$(docker inspect -f '{{range .Mounts}}{{.Destination}} {{end}}' "$CONTAINER")"
  case "$MOUNTS" in
    *secrets*) fail "A2. el contenedor api monta una ruta de secretos: $MOUNTS" ;;
    *) pass "A2. el contenedor api no monta ninguna ruta de secretos (montajes: $MOUNTS)" ;;
  esac
  RESULT="$(docker exec "$CONTAINER" node -e "$READ_JS")"
  [ "$RESULT" = "ENOENT" ] && pass "A3. node -e \"fs.readFileSync('/run/secrets/signer-private-key.pem')\" desde api → $RESULT (la clave no está montada)" \
    || fail "A3. la lectura desde api devolvió '$RESULT' en lugar de ENOENT"
fi

# B y C. Volumen con la clave con los dueños y permisos reales: 10001:10001, modo 0400.
KEYS="p15-api-keys-$$"
cleanup() { docker volume rm "$KEYS" >/dev/null 2>&1; }
trap cleanup EXIT
docker volume create "$KEYS" >/dev/null || { echo "No se pudo crear el volumen de prueba"; exit 2; }
docker run --rm --user 0:0 --entrypoint node -v "$KEYS:/run/secrets" "$IMAGE" -e "
const fs = require('node:fs');
const { generateKeyPairSync } = require('node:crypto');
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
fs.writeFileSync('/run/secrets/signer-private-key.pem', privateKey.export({ type: 'pkcs8', format: 'pem' }));
fs.chownSync('/run/secrets/signer-private-key.pem', 10001, 10001);
fs.chmodSync('/run/secrets/signer-private-key.pem', 0o400);
" || { echo "No se pudo preparar la clave de prueba"; exit 2; }
STAT="$(docker run --rm --user 0:0 --entrypoint sh -v "$KEYS:/run/secrets:ro" "$IMAGE" -c "stat -c '%u:%g %a' /run/secrets/signer-private-key.pem")"
echo "      (clave de prueba efímera en un volumen: dueño:grupo y modo = $STAT)"

# B. La API: usuario 10002 + grupo suplementario 10001, como en el compose, con el mismo endurecimiento.
RESULT_B="$(docker run --rm --user 10002:10002 --group-add 10001 --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --entrypoint node -v "$KEYS:/run/secrets:ro" "$IMAGE" -e "$READ_JS")"
[ "$RESULT_B" = "EACCES" ] && pass "B.  con la clave montada (10001:10001, 0400), api (10002 + grupo 10001) → $RESULT_B" \
  || fail "B.  la API obtuvo '$RESULT_B' en lugar de EACCES"

# C. Control: el dueño sí la lee.
RESULT_C="$(docker run --rm --user 10001:10001 --read-only --cap-drop ALL \
  --entrypoint node -v "$KEYS:/run/secrets:ro" "$IMAGE" -e "$READ_JS")"
[ "$RESULT_C" = "LEIDA" ] && pass "C.  control: el usuario 10001 (firmante) sí la lee → $RESULT_C" \
  || fail "C.  el control falló: el usuario 10001 obtuvo '$RESULT_C'"

echo
if [ "$FAILED" = "0" ]; then
  echo "RESULTADO: P15 (lado API) APROBADA — ENOENT por no estar montada y EACCES aunque se montara."
else
  echo "RESULTADO: P15 (lado API) FALLA."
fi
exit "$FAILED"
