import { useEffect, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  ClipboardCheck,
  FileClock,
  Gauge,
  KeyRound,
  LogOut,
  Menu,
  MessageSquareLock,
  ScrollText,
  Shield,
  Users,
  X,
} from 'lucide-react'

import { useAuth } from '../auth/context'
import { cx } from '../lib/format'
import { ErrorBoundary } from './ErrorBoundary'

function Item({ to, icon, children, onClick }: { to: string; icon: ReactNode; children: ReactNode; onClick?: () => void }) {
  return (
    <NavLink
      to={to}
      end
      onClick={onClick}
      className={({ isActive }) =>
        cx(
          'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition',
          isActive ? 'bg-[var(--sidebar-active)] font-medium text-white' : 'text-[var(--sidebar-text)] hover:bg-[var(--sidebar-active)]',
        )
      }
    >
      {icon}
      {children}
    </NavLink>
  )
}

export function Layout() {
  const { user, logout } = useAuth()
  const [open, setOpen] = useState(false)
  const close = () => setOpen(false)
  const icon = 'size-4'
  const { pathname } = useLocation()
  // A new page starts at the top, not at the previous page's scroll offset.
  // Block body on purpose: newer browsers return a Promise from scrollTo, and an
  // effect must return nothing or a cleanup function.
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [pathname])

  const nav = (
    <nav className="flex flex-1 flex-col gap-1" aria-label="Main">
      <div className="px-3 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Workspace</div>
      <Item to="/" icon={<MessageSquareLock className={icon} />} onClick={close}>Playground</Item>
      <Item to="/approvals" icon={<FileClock className={icon} />} onClick={close}>My approvals</Item>
      <Item to="/keys" icon={<KeyRound className={icon} />} onClick={close}>API keys</Item>
      {user?.role === 'admin' && (
        <>
          <div className="px-3 pb-1 pt-5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Administration</div>
          <Item to="/admin" icon={<Gauge className={icon} />} onClick={close}>Overview</Item>
          <Item to="/admin/approvals" icon={<ClipboardCheck className={icon} />} onClick={close}>Approval queue</Item>
          <Item to="/admin/audit" icon={<ScrollText className={icon} />} onClick={close}>Audit log</Item>
          <Item to="/admin/users" icon={<Users className={icon} />} onClick={close}>Users</Item>
          <Item to="/admin/policy" icon={<Shield className={icon} />} onClick={close}>Policy</Item>
        </>
      )}
    </nav>
  )

  return (
    <div className="flex min-h-full">
      <aside
        className={cx(
          'fixed inset-y-0 left-0 z-30 flex w-64 flex-col bg-[var(--sidebar)] p-4 transition-transform lg:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="mb-6 flex items-center justify-between px-2">
          <div className="flex items-center gap-2 text-white">
            <Shield className="size-6 text-blue-400" aria-hidden />
            <div>
              <div className="text-sm font-semibold leading-tight">Shadow AI Guardrail</div>
              <div className="text-[11px] text-slate-400">AI security gateway</div>
            </div>
          </div>
          <button className="text-slate-400 lg:hidden" onClick={close} aria-label="Close menu"><X className="size-5" /></button>
        </div>
        {nav}
        <div className="mt-4 border-t border-slate-800 pt-4">
          <div className="px-2 text-sm text-white">{user?.username}</div>
          <div className="px-2 text-xs capitalize text-slate-400">{user?.role}</div>
          <button
            onClick={() => void logout()}
            className="mt-3 flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-[var(--sidebar-text)] hover:bg-[var(--sidebar-active)]"
          >
            <LogOut className={icon} aria-hidden /> Sign out
          </button>
        </div>
      </aside>
      {open && <div className="fixed inset-0 z-20 bg-black/40 lg:hidden" onClick={close} aria-hidden />}
      <div className="flex min-w-0 flex-1 flex-col lg:pl-64">
        <header className="sticky top-0 z-10 flex items-center gap-3 border-b bg-[var(--surface)] px-4 py-3 lg:hidden" style={{ borderColor: 'var(--border)' }}>
          <button onClick={() => setOpen(true)} aria-label="Open menu"><Menu className="size-5" /></button>
          <span className="text-sm font-semibold">Shadow AI Guardrail</span>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 p-4 sm:p-6 lg:p-8">
          <ErrorBoundary key={pathname}><Outlet /></ErrorBoundary>
        </main>
      </div>
    </div>
  )
}
