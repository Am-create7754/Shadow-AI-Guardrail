import { lazy, Suspense, type ReactNode } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'

import { useAuth } from './auth/context'
import { Layout } from './components/Layout'
import { Spinner } from './components/ui'
import { ApiKeysPage } from './pages/ApiKeysPage'
import { LoginPage } from './pages/LoginPage'
import { MyApprovalsPage } from './pages/MyApprovalsPage'
import { PlaygroundPage } from './pages/PlaygroundPage'

// Admin screens (and the charting library) load on demand: developers never download them.
const AdminApprovalsPage = lazy(() => import('./pages/admin/AdminApprovalsPage').then((m) => ({ default: m.AdminApprovalsPage })))
const AuditLogPage = lazy(() => import('./pages/admin/AuditLogPage').then((m) => ({ default: m.AuditLogPage })))
const OverviewPage = lazy(() => import('./pages/admin/OverviewPage').then((m) => ({ default: m.OverviewPage })))
const PolicyPage = lazy(() => import('./pages/admin/PolicyPage').then((m) => ({ default: m.PolicyPage })))
const UsersPage = lazy(() => import('./pages/admin/UsersPage').then((m) => ({ default: m.UsersPage })))

/** Hides admin screens from non-admins. The API enforces the same rule on
 *  every request - this only keeps the UI honest. */
function AdminOnly({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  if (user?.role !== 'admin') return <Navigate to="/" replace />
  return <Suspense fallback={<Spinner />}>{children}</Suspense>
}

export default function App() {
  const { user } = useAuth()
  if (!user) return <LoginPage />
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<PlaygroundPage />} />
        <Route path="approvals" element={<MyApprovalsPage />} />
        <Route path="keys" element={<ApiKeysPage />} />
        <Route path="admin" element={<AdminOnly><OverviewPage /></AdminOnly>} />
        <Route path="admin/approvals" element={<AdminOnly><AdminApprovalsPage /></AdminOnly>} />
        <Route path="admin/audit" element={<AdminOnly><AuditLogPage /></AdminOnly>} />
        <Route path="admin/users" element={<AdminOnly><UsersPage /></AdminOnly>} />
        <Route path="admin/policy" element={<AdminOnly><PolicyPage /></AdminOnly>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
