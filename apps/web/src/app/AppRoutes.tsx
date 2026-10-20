import { Route, Routes } from 'react-router'
import { Layout } from '../components/Layout.tsx'
import { AuditPage } from '../features/audit/AuditPage.tsx'
import { ProtectedRoute } from '../features/auth/ProtectedRoute.tsx'
import { LoginPage } from '../features/auth/LoginPage.tsx'
import { DashboardPage } from '../features/dashboard/DashboardPage.tsx'
import { DraftsPage } from '../features/dashboard/DraftsPage.tsx'
import { UsersPage } from '../features/dashboard/UsersPage.tsx'
import { CryptoLabPage } from '../features/verification/CryptoLabPage.tsx'
import { HomePage } from '../pages/HomePage.tsx'
import { NotFoundPage } from '../pages/NotFoundPage.tsx'

/** Tabla de rutas. El control de acceso real está en la API; aquí solo se guía la interfaz. */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<HomePage />} />
        <Route path="login" element={<LoginPage />} />
        <Route path="laboratorio/criptografia" element={<CryptoLabPage />} />
        <Route path="panel" element={<ProtectedRoute />}>
          <Route index element={<DashboardPage />} />
          <Route element={<ProtectedRoute permission="users:read" />}>
            <Route path="usuarios" element={<UsersPage />} />
          </Route>
          <Route element={<ProtectedRoute permission="drafts:read-own" />}>
            <Route path="borradores" element={<DraftsPage />} />
          </Route>
          <Route element={<ProtectedRoute permission="audit:read" />}>
            <Route path="auditoria" element={<AuditPage />} />
          </Route>
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
