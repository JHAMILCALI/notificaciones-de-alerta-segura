import { createContext, useContext } from 'react'
import { api, type ApiClient } from './api.ts'

export const ApiContext = createContext<ApiClient>(api)

/** Cliente de la API inyectable (las pruebas proporcionan uno con `fetch` simulado). */
export function useApi(): ApiClient {
  return useContext(ApiContext)
}
