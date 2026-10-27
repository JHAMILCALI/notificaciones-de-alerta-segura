-- S2-12: tablas de la alerta firmada. AlertaPublicada, EventoAlerta y EstadoAlerta son INMUTABLES:
-- el rol de la app solo recibirá SELECT e INSERT (pnpm db:roles) y, además, un trigger bloquea
-- UPDATE, DELETE y TRUNCATE incluso al propietario. ClavePublica es solo inventario (no es autoridad).
-- Las FK de las tres tablas inmutables van sin ON DELETE CASCADE: nada se borra en cascada.

-- CreateTable
CREATE TABLE "AlertaPublicada" (
    "id" UUID NOT NULL,
    "emisorId" UUID NOT NULL,
    "draftId" UUID NOT NULL,
    "payloadCanonico" BYTEA NOT NULL,
    "hashPayload" TEXT NOT NULL,
    "firma" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "publishedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "tipo" "TipoAlerta" NOT NULL,
    "departamento" "Departamento" NOT NULL,
    "municipio" TEXT,
    "severidad" "NivelAlerta" NOT NULL,
    "mensaje" TEXT NOT NULL,
    "emitidaEn" TIMESTAMPTZ(3) NOT NULL,
    "expiraEn" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "AlertaPublicada_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EventoAlerta" (
    "id" UUID NOT NULL,
    "alertaId" UUID NOT NULL,
    "payloadCanonico" BYTEA NOT NULL,
    "hashEvento" TEXT NOT NULL,
    "hashAlerta" TEXT NOT NULL,
    "firma" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EventoAlerta_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EstadoAlerta" (
    "id" UUID NOT NULL,
    "alertaId" UUID NOT NULL,
    "secuencia" INTEGER NOT NULL,
    "payloadCanonico" BYTEA NOT NULL,
    "hashPayload" TEXT NOT NULL,
    "firma" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EstadoAlerta_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClavePublica" (
    "keyId" TEXT NOT NULL,
    "jwk" JSONB NOT NULL,
    "versionRegistro" INTEGER NOT NULL,
    "creadoEn" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ClavePublica_pkey" PRIMARY KEY ("keyId")
);

-- CreateIndex
CREATE UNIQUE INDEX "AlertaPublicada_draftId_key" ON "AlertaPublicada"("draftId");

-- CreateIndex
CREATE UNIQUE INDEX "AlertaPublicada_hashPayload_key" ON "AlertaPublicada"("hashPayload");

-- CreateIndex
CREATE INDEX "AlertaPublicada_publishedAt_idx" ON "AlertaPublicada"("publishedAt" DESC);

-- CreateIndex
CREATE INDEX "AlertaPublicada_emisorId_publishedAt_idx" ON "AlertaPublicada"("emisorId", "publishedAt" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "AlertaPublicada_id_hashPayload_key" ON "AlertaPublicada"("id", "hashPayload");

-- CreateIndex
CREATE UNIQUE INDEX "EventoAlerta_alertaId_key" ON "EventoAlerta"("alertaId");

-- CreateIndex
CREATE UNIQUE INDEX "EventoAlerta_hashEvento_key" ON "EventoAlerta"("hashEvento");

-- CreateIndex
CREATE UNIQUE INDEX "EventoAlerta_alertaId_hashAlerta_key" ON "EventoAlerta"("alertaId", "hashAlerta");

-- CreateIndex
CREATE INDEX "EstadoAlerta_alertaId_secuencia_createdAt_idx" ON "EstadoAlerta"("alertaId", "secuencia" DESC, "createdAt" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "Draft_alertaId_key" ON "Draft"("alertaId");

-- AddForeignKey
ALTER TABLE "Draft" ADD CONSTRAINT "Draft_alertaId_fkey" FOREIGN KEY ("alertaId") REFERENCES "AlertaPublicada"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AlertaPublicada" ADD CONSTRAINT "AlertaPublicada_emisorId_fkey" FOREIGN KEY ("emisorId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AlertaPublicada" ADD CONSTRAINT "AlertaPublicada_draftId_fkey" FOREIGN KEY ("draftId") REFERENCES "Draft"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventoAlerta" ADD CONSTRAINT "EventoAlerta_alertaId_hashAlerta_fkey" FOREIGN KEY ("alertaId", "hashAlerta") REFERENCES "AlertaPublicada"("id", "hashPayload") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EstadoAlerta" ADD CONSTRAINT "EstadoAlerta_alertaId_fkey" FOREIGN KEY ("alertaId") REFERENCES "AlertaPublicada"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- Integridad de formato. Los documentos firmados fijan estos formatos (packages/shared/src/schemas/documents.ts).
-- La base recalcula el SHA-256 de los bytes guardados: un hash que no corresponde a payloadCanonico no entra.
ALTER TABLE "AlertaPublicada"
  ADD CONSTRAINT "AlertaPublicada_hashPayload_chk" CHECK ("hashPayload" = encode(sha256("payloadCanonico"), 'hex')),
  ADD CONSTRAINT "AlertaPublicada_firma_chk" CHECK ("firma" ~ '^[A-Za-z0-9_-]{86}$'),
  ADD CONSTRAINT "AlertaPublicada_keyId_chk" CHECK ("keyId" ~ '^[A-Za-z0-9_-]{43}$'),
  ADD CONSTRAINT "AlertaPublicada_mensaje_chk" CHECK (char_length("mensaje") BETWEEN 1 AND 1000),
  ADD CONSTRAINT "AlertaPublicada_vigencia_chk" CHECK ("expiraEn" > "emitidaEn");

ALTER TABLE "EventoAlerta"
  ADD CONSTRAINT "EventoAlerta_hashEvento_chk" CHECK ("hashEvento" = encode(sha256("payloadCanonico"), 'hex')),
  ADD CONSTRAINT "EventoAlerta_hashAlerta_chk" CHECK ("hashAlerta" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "EventoAlerta_firma_chk" CHECK ("firma" ~ '^[A-Za-z0-9_-]{86}$'),
  ADD CONSTRAINT "EventoAlerta_keyId_chk" CHECK ("keyId" ~ '^[A-Za-z0-9_-]{43}$');

ALTER TABLE "EstadoAlerta"
  ADD CONSTRAINT "EstadoAlerta_hashPayload_chk" CHECK ("hashPayload" = encode(sha256("payloadCanonico"), 'hex')),
  ADD CONSTRAINT "EstadoAlerta_firma_chk" CHECK ("firma" ~ '^[A-Za-z0-9_-]{86}$'),
  ADD CONSTRAINT "EstadoAlerta_keyId_chk" CHECK ("keyId" ~ '^[A-Za-z0-9_-]{43}$'),
  ADD CONSTRAINT "EstadoAlerta_secuencia_chk" CHECK ("secuencia" >= 0);

ALTER TABLE "ClavePublica"
  ADD CONSTRAINT "ClavePublica_keyId_chk" CHECK ("keyId" ~ '^[A-Za-z0-9_-]{43}$'),
  ADD CONSTRAINT "ClavePublica_versionRegistro_chk" CHECK ("versionRegistro" >= 1);

-- Inmutabilidad: se rechazan UPDATE, DELETE y TRUNCATE (mismo patrón que AuditLog). Con el rol de la app
-- el permiso falla antes (42501, P07); el trigger cubre también al propietario.
CREATE OR REPLACE FUNCTION "tabla_inmutable"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% es inmutable: % no permitido', TG_TABLE_NAME, TG_OP;
END;
$$;

CREATE TRIGGER "AlertaPublicada_inmutable"
  BEFORE UPDATE OR DELETE ON "AlertaPublicada"
  FOR EACH ROW EXECUTE FUNCTION "tabla_inmutable"();
CREATE TRIGGER "AlertaPublicada_no_truncate"
  BEFORE TRUNCATE ON "AlertaPublicada"
  FOR EACH STATEMENT EXECUTE FUNCTION "tabla_inmutable"();

CREATE TRIGGER "EventoAlerta_inmutable"
  BEFORE UPDATE OR DELETE ON "EventoAlerta"
  FOR EACH ROW EXECUTE FUNCTION "tabla_inmutable"();
CREATE TRIGGER "EventoAlerta_no_truncate"
  BEFORE TRUNCATE ON "EventoAlerta"
  FOR EACH STATEMENT EXECUTE FUNCTION "tabla_inmutable"();

CREATE TRIGGER "EstadoAlerta_inmutable"
  BEFORE UPDATE OR DELETE ON "EstadoAlerta"
  FOR EACH ROW EXECUTE FUNCTION "tabla_inmutable"();
CREATE TRIGGER "EstadoAlerta_no_truncate"
  BEFORE TRUNCATE ON "EstadoAlerta"
  FOR EACH STATEMENT EXECUTE FUNCTION "tabla_inmutable"();
