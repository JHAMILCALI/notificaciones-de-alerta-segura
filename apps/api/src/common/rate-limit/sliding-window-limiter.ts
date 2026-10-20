export interface LimitResult {
  allowed: boolean;
  /** Segundos hasta que se libera un hueco (solo si `allowed` es false; mínimo 1). */
  retryAfterSeconds: number;
  remaining: number;
}

interface Entry {
  hits: number[];
  windowMs: number;
}

/**
 * Ventana deslizante con registro de marcas de tiempo, en memoria del proceso.
 * Solo las solicitudes permitidas consumen cupo: un cliente bloqueado no prolonga su bloqueo.
 * Limitación conocida (semana 1): no se comparte entre instancias ni sobrevive a un reinicio.
 */
export class SlidingWindowLimiter {
  private readonly entries = new Map<string, Entry>();

  constructor(private readonly maxKeys = 100_000) {}

  private prune(entry: Entry, now: number): void {
    const cutoff = now - entry.windowMs;
    let drop = 0;
    while (drop < entry.hits.length && entry.hits[drop] <= cutoff) drop++;
    if (drop > 0) entry.hits.splice(0, drop);
  }

  /** Consulta sin consumir cupo. */
  peek(
    key: string,
    limit: number,
    windowMs: number,
    now = Date.now(),
  ): LimitResult {
    const entry = this.entries.get(key);
    if (!entry)
      return { allowed: true, retryAfterSeconds: 0, remaining: limit };
    entry.windowMs = windowMs;
    this.prune(entry, now);
    return this.result(entry, limit, windowMs, now);
  }

  /** Consume un cupo si lo hay. */
  consume(
    key: string,
    limit: number,
    windowMs: number,
    now = Date.now(),
  ): LimitResult {
    let entry = this.entries.get(key);
    if (!entry) {
      this.ensureCapacity(now);
      entry = { hits: [], windowMs };
      this.entries.set(key, entry);
    }
    entry.windowMs = windowMs;
    this.prune(entry, now);
    const result = this.result(entry, limit, windowMs, now);
    if (result.allowed) {
      entry.hits.push(now);
      return { ...result, remaining: result.remaining - 1 };
    }
    return result;
  }

  /** Registra un evento sin comprobar (p. ej. un intento fallido tras la comprobación previa). */
  record(key: string, windowMs: number, now = Date.now()): void {
    let entry = this.entries.get(key);
    if (!entry) {
      this.ensureCapacity(now);
      entry = { hits: [], windowMs };
      this.entries.set(key, entry);
    }
    entry.windowMs = windowMs;
    entry.hits.push(now);
  }

  private result(
    entry: Entry,
    limit: number,
    windowMs: number,
    now: number,
  ): LimitResult {
    if (entry.hits.length < limit) {
      return {
        allowed: true,
        retryAfterSeconds: 0,
        remaining: limit - entry.hits.length,
      };
    }
    // El hueco se libera cuando caduca la marca que deja el recuento por debajo del límite.
    const pivot = entry.hits[entry.hits.length - limit];
    const waitMs = Math.max(pivot + windowMs - now, 0);
    return {
      allowed: false,
      retryAfterSeconds: Math.max(Math.ceil(waitMs / 1000), 1),
      remaining: 0,
    };
  }

  /** Elimina claves inactivas; llamado periódicamente y antes de crecer por encima del tope. */
  sweep(now = Date.now()): void {
    for (const [key, entry] of this.entries) {
      this.prune(entry, now);
      if (entry.hits.length === 0) this.entries.delete(key);
    }
  }

  private ensureCapacity(now: number): void {
    if (this.entries.size < this.maxKeys) return;
    this.sweep(now);
    // Si sigue lleno, se descarta la clave más antigua: se prefiere perder memoria de un
    // cliente a agotar la memoria del proceso.
    while (this.entries.size >= this.maxKeys) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
  }

  get size(): number {
    return this.entries.size;
  }
}
