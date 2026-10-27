import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { errorResponse, makeFetch, renderApp } from '../../test/helpers.tsx'
import { evaluate, labFixture, prettyJson, tamperField } from './lab.ts'

describe('laboratorio criptográfico (evidencia visual de P13)', () => {
  it('verifica en el navegador todos los vectores generados en Node', async () => {
    const fetchMock = makeFetch(() => errorResponse(401, 'UNAUTHENTICATED', 'x'))
    renderApp({ fetchMock, route: '/laboratorio/criptografia' })

    const total = labFixture.vectors.length
    await waitFor(() =>
      expect(screen.getByTestId('baseline-summary')).toHaveTextContent(`${total} de ${total} verificados correctamente`),
    )
    await waitFor(() => expect(screen.getByTestId('lab-result')).toHaveTextContent('Firma válida'))
  })

  it('rechaza el contenido alterado y vuelve a validar al restaurar', async () => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = makeFetch(() => errorResponse(401, 'UNAUTHENTICATED', 'x'))
    renderApp({ fetchMock, route: '/laboratorio/criptografia' })

    await waitFor(() => expect(screen.getByTestId('lab-result')).toHaveTextContent('Firma válida'))

    await user.click(screen.getByRole('button', { name: 'Alterar un campo' }))
    await waitFor(() => expect(screen.getByTestId('lab-result')).toHaveTextContent('Firma INVÁLIDA'))

    await user.click(screen.getByRole('button', { name: 'Restaurar original' }))
    await waitFor(() => expect(screen.getByTestId('lab-result')).toHaveTextContent('Firma válida'))

    await user.click(screen.getByRole('button', { name: 'Alterar un bit de la firma' }))
    await waitFor(() => expect(screen.getByTestId('lab-result')).toHaveTextContent('Firma INVÁLIDA'))

    await user.click(screen.getByRole('button', { name: 'Restaurar original' }))
    await user.click(screen.getByRole('button', { name: 'Añadir una clave' }))
    await waitFor(() => expect(screen.getByTestId('lab-result')).toHaveTextContent('Firma INVÁLIDA'))
  })
})

describe('lab.evaluate', () => {
  const vector = labFixture.vectors[0]!

  it('el orden de las claves no afecta (JCS) y un cambio de valor sí', async () => {
    const reordered = JSON.stringify(Object.fromEntries(Object.entries(vector.document as object).reverse()))
    expect((await evaluate(reordered, vector.signature)).outcome).toBe('valid')
    expect((await evaluate(tamperField(prettyJson(vector.document)), vector.signature)).outcome).toBe('invalid')
  })

  it('JSON mal formado es un error, no una verificación', async () => {
    const result = await evaluate('{ no es json', vector.signature)
    expect(result.outcome).toBe('error')
  })

  it('una firma mal codificada se rechaza sin lanzar', async () => {
    expect((await evaluate(prettyJson(vector.document), '***')).outcome).toBe('invalid')
  })
})
