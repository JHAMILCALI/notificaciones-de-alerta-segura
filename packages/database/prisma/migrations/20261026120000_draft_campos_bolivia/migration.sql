-- S2-10 (D-4, opción C): el borrador pasa a los campos oficiales de Bolivia.
-- tipo, zona (departamento + municipio), severidad (AMARILLA/NARANJA/ROJA), mensaje, vigencia en horas,
-- estado DRAFT/PUBLISHED y alertaId (la alerta publicada a partir del borrador; su FK llega con las tablas
-- inmutables de la entrega 2).

CREATE TYPE "TipoAlerta" AS ENUM (
  'LLUVIAS_INTENSAS', 'TORMENTA_ELECTRICA', 'GRANIZADA', 'NEVADA', 'HELADA', 'OLA_DE_FRIO', 'OLA_DE_CALOR',
  'VIENTOS_FUERTES', 'INUNDACION', 'DESBORDE_DE_RIO', 'MAZAMORRA', 'SEQUIA', 'INCENDIO_FORESTAL',
  'RADIACION_UV_EXTREMA'
);

CREATE TYPE "Departamento" AS ENUM (
  'LA_PAZ', 'ORURO', 'POTOSI', 'COCHABAMBA', 'CHUQUISACA', 'TARIJA', 'SANTA_CRUZ', 'BENI', 'PANDO'
);

CREATE TYPE "NivelAlerta" AS ENUM ('AMARILLA', 'NARANJA', 'ROJA');

ALTER TYPE "DraftStatus" ADD VALUE 'PUBLISHED';

-- Se añaden con valores por defecto solo para poder migrar las filas existentes; luego se retiran.
ALTER TABLE "Draft"
  ADD COLUMN "tipo" "TipoAlerta" NOT NULL DEFAULT 'LLUVIAS_INTENSAS',
  ADD COLUMN "departamento" "Departamento" NOT NULL DEFAULT 'LA_PAZ',
  ADD COLUMN "municipio" TEXT,
  ADD COLUMN "severidad" "NivelAlerta",
  ADD COLUMN "mensaje" TEXT,
  ADD COLUMN "vigenciaHoras" INTEGER NOT NULL DEFAULT 24,
  ADD COLUMN "alertaId" UUID;

UPDATE "Draft" SET
  "severidad" = CASE "severity"
    WHEN 'INFO' THEN 'AMARILLA'::"NivelAlerta"
    WHEN 'WARNING' THEN 'NARANJA'::"NivelAlerta"
    ELSE 'ROJA'::"NivelAlerta"
  END,
  "mensaje" = left(btrim("title") || E'\n' || btrim("body"), 1000);

ALTER TABLE "Draft"
  ALTER COLUMN "severidad" SET NOT NULL,
  ALTER COLUMN "mensaje" SET NOT NULL,
  ALTER COLUMN "tipo" DROP DEFAULT,
  ALTER COLUMN "departamento" DROP DEFAULT,
  ALTER COLUMN "vigenciaHoras" DROP DEFAULT,
  DROP COLUMN "title",
  DROP COLUMN "body",
  DROP COLUMN "severity";

DROP TYPE "Severity";

-- Mismos límites que CreateDraftRequestSchema (packages/shared): vigencia de 1 a 72 h, mensaje de 10 a 1000.
ALTER TABLE "Draft"
  ADD CONSTRAINT "Draft_vigenciaHoras_check" CHECK ("vigenciaHoras" BETWEEN 1 AND 72),
  ADD CONSTRAINT "Draft_mensaje_check" CHECK (char_length("mensaje") BETWEEN 1 AND 1000);
