import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, parse, relative, resolve, sep } from 'node:path';
import { CliError } from './errors.ts';

/** Directorio de la raíz de laboratorio: fuera de cualquier repositorio. */
export function defaultRootDir(): string {
  return join(homedir(), '.alertasegura-lab', 'root');
}

/** Resuelve `target` aunque no exista: `realpath` del ancestro existente más cercano + el resto. */
function resolveReal(target: string): string {
  const absolute = resolve(target);
  const tail: string[] = [];
  let current = absolute;
  while (!existsSync(current)) {
    const parent = dirname(current);
    if (parent === current) return absolute;
    tail.unshift(parse(current).base);
    current = parent;
  }
  return join(realpathSync(current), ...tail);
}

/**
 * Un `.git` válido es una carpeta con HEAD o, en un worktree, un archivo `gitdir: ...`. Una carpeta `.git`
 * vacía o ajena (por ejemplo restos de una herramienta en el perfil de usuario) no cuenta como repositorio.
 */
function isGitMarker(path: string): boolean {
  try {
    const info = statSync(path);
    if (info.isDirectory()) return existsSync(join(path, 'HEAD'));
    return info.isFile() && readFileSync(path, 'utf8').startsWith('gitdir:');
  } catch {
    return false;
  }
}

/** Raíz del repositorio Git (carpeta con `.git`, que en un worktree es un archivo) o null. */
export function findRepoRoot(target: string): string | null {
  let current = dirname(resolveReal(target));
  for (;;) {
    if (isGitMarker(join(current, '.git'))) return current;
    const parent = dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function insideRepo(target: string): { repoRoot: string; rel: string } | null {
  const real = resolveReal(target);
  const repoRoot = findRepoRoot(real);
  if (repoRoot === null) return null;
  const rel = relative(repoRoot, real);
  if (rel.startsWith('..') || rel === '') return null;
  return { repoRoot, rel };
}

/** La clave raíz nunca puede quedar dentro de un repositorio, ni siquiera en `secrets/`. */
export function assertOutsideRepo(target: string, what: string): string {
  const absolute = resolve(target);
  if (insideRepo(absolute) !== null) {
    throw new CliError('PATH_INSIDE_REPO', `${what} no puede estar dentro de un repositorio Git: ${absolute}`);
  }
  return absolute;
}

/**
 * Material privado del firmante: se admite fuera del repositorio o dentro de una carpeta `secrets/`
 * (ignorada por Git). Cualquier otra ruta dentro del repositorio se rechaza.
 */
export function assertPrivateOutputAllowed(target: string, what: string): string {
  const absolute = resolve(target);
  const found = insideRepo(absolute);
  if (found !== null) {
    const directories = found.rel.split(sep).slice(0, -1);
    if (!directories.includes('secrets')) {
      throw new CliError(
        'PRIVATE_PATH_IN_REPO',
        `${what} solo puede escribirse dentro del repositorio en una carpeta secrets/ (ignorada por Git): ${absolute}`,
      );
    }
  }
  return absolute;
}
