import { SlidingWindowLimiter } from './sliding-window-limiter';

describe('SlidingWindowLimiter', () => {
  const WINDOW = 60_000;

  it('permite hasta el límite y luego bloquea con Retry-After', () => {
    const limiter = new SlidingWindowLimiter();
    const t0 = 1_000_000;
    for (let i = 0; i < 3; i++) {
      expect(limiter.consume('k', 3, WINDOW, t0 + i * 1000).allowed).toBe(true);
    }
    const denied = limiter.consume('k', 3, WINDOW, t0 + 3000);
    expect(denied.allowed).toBe(false);
    // la marca más antigua (t0) caduca en t0 + 60 s; faltan 57 s
    expect(denied.retryAfterSeconds).toBe(57);
  });

  it('libera cupo al deslizar la ventana', () => {
    const limiter = new SlidingWindowLimiter();
    const t0 = 5_000_000;
    limiter.consume('k', 1, WINDOW, t0);
    expect(limiter.consume('k', 1, WINDOW, t0 + 1).allowed).toBe(false);
    expect(limiter.consume('k', 1, WINDOW, t0 + WINDOW + 1).allowed).toBe(true);
  });

  it('las solicitudes bloqueadas no prolongan el bloqueo', () => {
    const limiter = new SlidingWindowLimiter();
    const t0 = 9_000_000;
    limiter.consume('k', 1, WINDOW, t0);
    for (let i = 1; i <= 50; i++) limiter.consume('k', 1, WINDOW, t0 + i * 100);
    expect(limiter.consume('k', 1, WINDOW, t0 + WINDOW + 1).allowed).toBe(true);
  });

  it('claves independientes', () => {
    const limiter = new SlidingWindowLimiter();
    limiter.consume('a', 1, WINDOW, 1);
    expect(limiter.consume('a', 1, WINDOW, 2).allowed).toBe(false);
    expect(limiter.consume('b', 1, WINDOW, 2).allowed).toBe(true);
  });

  it('peek no consume y record sí cuenta', () => {
    const limiter = new SlidingWindowLimiter();
    expect(limiter.peek('k', 2, WINDOW, 1).allowed).toBe(true);
    expect(limiter.peek('k', 2, WINDOW, 2).remaining).toBe(2);
    limiter.record('k', WINDOW, 3);
    limiter.record('k', WINDOW, 4);
    expect(limiter.peek('k', 2, WINDOW, 5).allowed).toBe(false);
  });

  it('sweep elimina claves caducadas y el tope de claves acota la memoria', () => {
    const limiter = new SlidingWindowLimiter(3);
    limiter.consume('a', 1, 1000, 0);
    limiter.consume('b', 1, 1000, 0);
    limiter.consume('c', 1, 1000, 0);
    limiter.consume('d', 1, 1000, 10_000); // purga las caducadas antes de insertar
    expect(limiter.size).toBeLessThanOrEqual(3);
    limiter.sweep(100_000);
    expect(limiter.size).toBe(0);
  });
});
