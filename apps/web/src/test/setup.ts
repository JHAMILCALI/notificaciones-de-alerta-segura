import '@testing-library/jest-dom/vitest'
import { cleanup, configure } from '@testing-library/react'
import { afterEach } from 'vitest'

// Con la máquina cargada (api, web y verification en paralelo) los 1000 ms por defecto de
// findBy/waitFor no bastan; se amplía solo la espera máxima, no se añaden pausas fijas.
configure({ asyncUtilTimeout: 5000 })

afterEach(() => {
  cleanup()
})
