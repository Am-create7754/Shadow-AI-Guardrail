import { Component, type ErrorInfo, type ReactNode } from 'react'

interface State {
  failed: boolean
}

/** Keeps a crashing page from blanking the whole app. Deliberately shows no
 *  error details: messages could echo data the page was rendering. */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  override state: State = { failed: false }

  static getDerivedStateFromError(): State {
    return { failed: true }
  }

  override componentDidCatch(error: unknown, info: ErrorInfo): void {
    console.error('page crashed', error instanceof Error ? error.name : typeof error, info.componentStack?.split('\n')[1]?.trim())
  }

  override render() {
    if (!this.state.failed) return this.props.children
    return (
      <div role="alert" className="rounded-xl border p-6 text-sm" style={{ borderColor: 'var(--border)' }}>
        <p className="font-semibold">This page failed to render.</p>
        <p className="mt-1 text-[var(--text-muted)]">Open another page from the menu, or reload to sign in again.</p>
      </div>
    )
  }
}
