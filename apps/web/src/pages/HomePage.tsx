import { Link } from 'react-router'

export function HomePage() {
  return (
    <>
      <section className="card" aria-labelledby="home-title">
        <h1 id="home-title">Alertas oficiales verificables</h1>
        <p>
          AlertaSegura permitirá a cualquier ciudadano comprobar, sin crear una cuenta, que una alerta fue emitida
          por una autoridad autorizada y que no fue alterada.
        </p>
      </section>
      <section className="card" aria-labelledby="consulta-title">
        <h2 id="consulta-title">Consulta ciudadana</h2>
        <p role="status">
          La consulta de alertas firmadas llegará en una próxima versión. Por ahora no hay alertas publicadas.
        </p>
        <p className="muted">
          Cuando esté disponible, cada alerta mostrará su firma digital y se verificará en tu propio navegador.
        </p>
      </section>
      <section className="card" aria-labelledby="lab-title">
        <h2 id="lab-title">Laboratorio criptográfico</h2>
        <p>
          Puedes ver ahora mismo cómo se verifica una firma ECDSA P-256 en el navegador y qué ocurre si el contenido
          se altera.
        </p>
        <Link className="button" to="/laboratorio/criptografia">
          Abrir el laboratorio
        </Link>
      </section>
    </>
  )
}
