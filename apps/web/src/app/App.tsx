import { BrowserRouter } from 'react-router'
import { AuthProvider } from '../features/auth/AuthProvider.tsx'
import { AppRoutes } from './AppRoutes.tsx'

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  )
}
