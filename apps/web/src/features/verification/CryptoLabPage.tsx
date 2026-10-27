import { useEffect, useState } from 'react'
import { addKey, evaluate, flipSignatureBit, labFixture, prettyJson, tamperField, type Evaluation } from './lab.ts'

const hasSubtle = typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.subtle !== 'undefined'

function StatusBadge({ result }: { result: Evaluation | null }) {
  if (result === null) return <span className="badge">Verificando…</span>
  if (result.outcome === 'valid') return <span className="badge ok">Firma válida</span>
  if (result.outcome === 'invalid') return <span className="badge bad">Firma INVÁLIDA: contenido alterado</span>
  return <span className="badge warn">No verificable</span>
}

/** Verifica cada vector tal como fue emitido por Node. */
function useBaselineResults(): Record<string, Evaluation> {
  const [results, setResults] = useState<Record<string, Evaluation>>({})
  useEffect(() => {
    if (!hasSubtle) return
    let cancelled = false
    void Promise.all(
      labFixture.vectors.map(async (vector) => {
        const result = await evaluate(prettyJson(vector.document), vector.signature)
        return [vector.id, result] as const
      }),
    ).then((entries) => {
      if (!cancelled) setResults(Object.fromEntries(entries))
    })
    return () => {
      cancelled = true
    }
  }, [])
  return results
}

export function CryptoLabPage() {
  const baseline = useBaselineResults()
  const [selectedId, setSelectedId] = useState(labFixture.vectors[0]?.id ?? '')
  const vector = labFixture.vectors.find((v) => v.id === selectedId) ?? labFixture.vectors[0]
  const [text, setText] = useState(() => (vector ? prettyJson(vector.document) : ''))
  const [signature, setSignature] = useState(vector?.signature ?? '')
  const [settled, setSettled] = useState<{ text: string; signature: string; result: Evaluation } | null>(null)
  // Mientras el resultado guardado no corresponda al texto y firma actuales, se muestra "Verificando…".
  const result = settled !== null && settled.text === text && settled.signature === signature ? settled.result : null

  function select(id: string) {
    const next = labFixture.vectors.find((v) => v.id === id)
    if (!next) return
    setSelectedId(id)
    setText(prettyJson(next.document))
    setSignature(next.signature)
  }

  useEffect(() => {
    if (!hasSubtle) return
    let cancelled = false
    void evaluate(text, signature).then((evaluation) => {
      if (!cancelled) setSettled({ text, signature, result: evaluation })
    })
    return () => {
      cancelled = true
    }
  }, [text, signature])

  if (!vector) {
    return (
      <section className="card">
        <h1>Laboratorio criptográfico</h1>
        <p role="alert" className="alert error">
          No hay vectores de prueba disponibles.
        </p>
      </section>
    )
  }

  const passed = labFixture.vectors.filter((v) => baseline[v.id]?.outcome === 'valid').length
  const baselineDone = Object.keys(baseline).length === labFixture.vectors.length

  return (
    <>
      <section className="card" aria-labelledby="lab-title">
        <h1 id="lab-title">Laboratorio criptográfico (P13)</h1>
        <p>
          Los vectores de este laboratorio fueron firmados en Node con una clave ECDSA P-256 efímera (ya descartada).
          Aquí se verifican en <strong>tu navegador</strong> con Web Crypto: canonicalización JSON (RFC 8785), SHA-256 y
          ECDSA con firma en formato IEEE P1363. Solo se usa la clave pública.
        </p>
        {!hasSubtle && (
          <p role="alert" className="alert error">
            Este navegador no ofrece Web Crypto (<code>crypto.subtle</code>). Usa HTTPS o <code>localhost</code>.
          </p>
        )}
        <dl className="kv">
          <dt>Algoritmo</dt>
          <dd>ECDSA P-256 / SHA-256, firma P1363 (64 bytes) en base64url</dd>
          <dt>kid</dt>
          <dd className="mono">{labFixture.publicKeyJwk.kid}</dd>
          <dt>Vectores originales</dt>
          <dd role="status" data-testid="baseline-summary">
            {baselineDone
              ? `${passed} de ${labFixture.vectors.length} verificados correctamente`
              : 'Verificando…'}
          </dd>
        </dl>
        <div className="table-wrap">
          <table>
            <caption className="sr-only">Resultado de la verificación de cada vector</caption>
            <thead>
              <tr>
                <th scope="col">Vector</th>
                <th scope="col">Descripción</th>
                <th scope="col">Resultado</th>
              </tr>
            </thead>
            <tbody>
              {labFixture.vectors.map((v) => (
                <tr key={v.id}>
                  <th scope="row">{v.id}</th>
                  <td>{v.description}</td>
                  <td>
                    <StatusBadge result={baseline[v.id] ?? null} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card" aria-labelledby="tamper-title">
        <h2 id="tamper-title">Alterar el contenido</h2>
        <p className="muted">
          Edita el documento o usa los botones: cualquier cambio, aunque sea de un carácter, invalida la firma.
        </p>
        <div className="field">
          <label htmlFor="lab-vector">Vector</label>
          <select id="lab-vector" value={selectedId} onChange={(event) => select(event.target.value)}>
            {labFixture.vectors.map((v) => (
              <option key={v.id} value={v.id}>
                {v.id}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="lab-doc">Documento JSON</label>
          <textarea
            id="lab-doc"
            className="mono"
            rows={12}
            spellCheck={false}
            value={text}
            onChange={(event) => setText(event.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="lab-sig">Firma (base64url, P1363)</label>
          <input
            id="lab-sig"
            className="mono"
            spellCheck={false}
            autoComplete="off"
            value={signature}
            onChange={(event) => setSignature(event.target.value)}
          />
        </div>
        <div className="actions">
          <button type="button" onClick={() => setText(tamperField(text))}>
            Alterar un campo
          </button>
          <button type="button" onClick={() => setText(addKey(text))}>
            Añadir una clave
          </button>
          <button
            type="button"
            onClick={() => {
              try {
                setSignature(flipSignatureBit(signature))
              } catch {
                setSignature(vector.signature)
              }
            }}
          >
            Alterar un bit de la firma
          </button>
          <button
            type="button"
            onClick={() => {
              setText(prettyJson(vector.document))
              setSignature(vector.signature)
            }}
          >
            Restaurar original
          </button>
        </div>

        <div role="status" aria-live="polite" className="result" data-testid="lab-result">
          <StatusBadge result={result} />
          {result?.outcome === 'error' && <p className="alert error">{result.message}</p>}
        </div>

        {result && result.outcome !== 'error' && (
          <dl className="kv">
            <dt>Forma canónica (RFC 8785)</dt>
            <dd className="mono wrap-anywhere" data-testid="lab-canonical">
              {result.canonical}
            </dd>
            <dt>SHA-256 de la forma canónica</dt>
            <dd className="mono wrap-anywhere">{result.sha256}</dd>
            <dt>Coincide con el original</dt>
            <dd>
              {result.canonical === vector.canonical ? 'Sí, idéntica al vector' : 'No, el contenido canónico difiere'}
            </dd>
          </dl>
        )}
      </section>
    </>
  )
}
