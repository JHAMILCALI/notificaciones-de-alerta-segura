import { Client } from 'pg';

/** Rol con el que corre la API (DATABASE_URL). Las migraciones y el seed usan el propietario. */
export const APP_ROLE = 'alertasegura_app';

type Privilege = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';

const APPEND_ONLY: Privilege[] = ['SELECT', 'INSERT'];

/**
 * Política de permisos del rol de la app (docs/coordination/api-contract-semana2.md). Es la fuente de verdad:
 * toda tabla del esquema `public` debe figurar aquí, de lo contrario `applyAppRole` falla en vez de
 * dejar un permiso por omisión. Nunca UPDATE, DELETE ni TRUNCATE sobre las tablas inmutables ni la auditoría (P07).
 */
export const APP_ROLE_POLICY: Readonly<Record<string, readonly Privilege[]>> = {
  AlertaPublicada: APPEND_ONLY,
  EventoAlerta: APPEND_ONLY,
  EstadoAlerta: APPEND_ONLY,
  ClavePublica: APPEND_ONLY,
  AuditLog: APPEND_ONLY,
  Draft: ['SELECT', 'INSERT', 'UPDATE'],
  User: ['SELECT', 'INSERT', 'UPDATE'],
  Session: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
};

/** Tablas sin ningún permiso para la app (metadatos de Prisma). */
const NO_ACCESS = new Set(['_prisma_migrations']);

export interface ApplyAppRoleOptions {
  /** Cadena de conexión con el rol propietario (DATABASE_MIGRATION_URL). */
  ownerConnectionString: string;
  /**
   * Contraseña del rol. Obligatoria si el rol aún no existe; si el rol ya existe y no se indica,
   * su contraseña no se toca.
   */
  password?: string;
}

export interface ApplyAppRoleResult {
  database: string;
  roleCreated: boolean;
  passwordSet: boolean;
  grants: Record<string, readonly Privilege[]>;
}

/**
 * Crea o actualiza `alertasegura_app` en la base a la que apunta la conexión. Idempotente: se puede
 * ejecutar tras cada migración. Los privilegios por defecto solo dan SELECT e INSERT en tablas futuras
 * (seguro para tablas append-only); si una tabla nueva necesita UPDATE o DELETE hay que declararla en
 * `APP_ROLE_POLICY`.
 */
export async function applyAppRole(options: ApplyAppRoleOptions): Promise<ApplyAppRoleResult> {
  const client = new Client({ connectionString: options.ownerConnectionString });
  await client.connect();
  try {
    await client.query('BEGIN');
    const role = client.escapeIdentifier(APP_ROLE);
    const database = (await client.query<{ db: string }>('SELECT current_database() AS db')).rows[0]?.db;
    if (!database) throw new Error('No se pudo determinar la base de datos actual');

    const exists = (await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [APP_ROLE])).rowCount === 1;
    if (!exists && !options.password) {
      throw new Error(`El rol ${APP_ROLE} no existe: se necesita APP_DB_PASSWORD para crearlo`);
    }
    const attributes = 'LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
    const passwordClause = options.password ? ` PASSWORD ${client.escapeLiteral(options.password)}` : '';
    await client.query(`${exists ? 'ALTER' : 'CREATE'} ROLE ${role} WITH ${attributes}${passwordClause}`);

    await client.query(`GRANT CONNECT ON DATABASE ${client.escapeIdentifier(database)} TO ${role}`);
    await client.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
    await client.query(`REVOKE CREATE ON SCHEMA public FROM ${role}`);
    await client.query(`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ${role}`);
    await client.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM ${role}`);

    const tables = (
      await client.query<{ tablename: string }>(
        `SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`,
      )
    ).rows.map((r) => r.tablename);
    const grants: Record<string, readonly Privilege[]> = {};
    for (const table of tables) {
      if (NO_ACCESS.has(table)) continue;
      const privileges = APP_ROLE_POLICY[table];
      if (!privileges) {
        throw new Error(
          `La tabla "${table}" no figura en APP_ROLE_POLICY (packages/database/src/roles.ts): declare sus permisos antes de continuar`,
        );
      }
      await client.query(`GRANT ${privileges.join(', ')} ON ${client.escapeIdentifier(table)} TO ${role}`);
      grants[table] = privileges;
    }

    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM ${role}`);
    await client.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT ON TABLES TO ${role}`);
    await client.query('COMMIT');
    return { database, roleCreated: !exists, passwordSet: Boolean(options.password), grants };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    await client.end();
  }
}
