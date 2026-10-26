import { Link } from 'react-router'

export function NotFoundPage() {
  return (
    <section className="card" aria-labelledby="nf-title">
      <h1 id="nf-title">Página no encontrada</h1>
      <p>
        <Link to="/alertas">Volver a las alertas</Link>
      </p>
    </section>
  )
}
