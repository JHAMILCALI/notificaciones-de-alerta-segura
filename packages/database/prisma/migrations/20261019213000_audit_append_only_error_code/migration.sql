-- El SQLSTATE restrict_violation (23001) lo traducen los controladores como violación de clave
-- foránea y oculta el motivo real. Se usa el SQLSTATE por defecto (P0001, raise_exception) para que
-- el mensaje "AuditLog es append-only" llegue intacto a quien intente modificar la auditoría.
CREATE OR REPLACE FUNCTION "audit_log_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'AuditLog es append-only: % no permitido', TG_OP;
END;
$$;
