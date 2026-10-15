import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { UserPlus } from 'lucide-react'

import { api } from '../../api/client'
import type { Role } from '../../api/types'
import { useAuth } from '../../auth/context'
import { Badge, Button, Card, ErrorBanner, Input, Label, PageHeader, Select, Spinner } from '../../components/ui'

export function UsersPage() {
  const { user: me } = useAuth()
  const qc = useQueryClient()
  const users = useQuery({ queryKey: ['users'], queryFn: api.users })
  const [form, setForm] = useState({ username: '', password: '', role: 'developer' as Role })
  const refresh = () => void qc.invalidateQueries({ queryKey: ['users'] })
  const create = useMutation({
    mutationFn: () => api.createUser(form.username, form.password, form.role),
    onSuccess: () => {
      setForm({ username: '', password: '', role: 'developer' })
      refresh()
    },
  })
  const toggle = useMutation({ mutationFn: ({ id, active }: { id: string; active: boolean }) => api.setUserActive(id, active), onSuccess: refresh })
  const nameOf = (id: string | null | undefined) => (id ? users.data?.find((u) => u.id === id)?.username ?? id : 'CLI')

  function submit(e: FormEvent) {
    e.preventDefault()
    create.mutate()
  }

  return (
    <div>
      <PageHeader
        title="Users"
        description="Roles are enforced by the API on every request. Deactivating a user ends their sessions immediately. Accounts record who created them, for separation of duties on approvals."
      />
      <ErrorBanner error={users.error ?? create.error ?? toggle.error} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <Card title="Create user">
          <form onSubmit={submit} className="space-y-3">
            <div><Label htmlFor="u-name">Username</Label><Input id="u-name" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required minLength={3} maxLength={64} autoComplete="off" /></div>
            <div><Label htmlFor="u-pass">Initial password (12+ characters)</Label><Input id="u-pass" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required minLength={12} autoComplete="new-password" /></div>
            <div><Label htmlFor="u-role">Role</Label>
              <Select id="u-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                <option value="developer">developer</option>
                <option value="admin">admin</option>
              </Select>
            </div>
            <Button type="submit" loading={create.isPending}><UserPlus className="size-4" aria-hidden /> Create</Button>
          </form>
        </Card>
        <Card title="All users">
          {users.isLoading ? <Spinner /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs text-[var(--text-muted)]">
                  <tr><th className="py-2 pr-3 font-medium">User</th><th className="py-2 pr-3 font-medium">Role</th><th className="py-2 pr-3 font-medium">Created by</th><th className="py-2 pr-3 font-medium">Status</th><th /></tr>
                </thead>
                <tbody>
                  {users.data?.map((u) => (
                    <tr key={u.id} className="border-t" style={{ borderColor: 'var(--border)' }}>
                      <td className="py-2 pr-3 font-medium">{u.username}{u.id === me?.id && <span className="ml-2 text-xs text-[var(--text-muted)]">(you)</span>}</td>
                      <td className="py-2 pr-3"><Badge tone={u.role === 'admin' ? 'warn' : 'neutral'}>{u.role}</Badge></td>
                      <td className="py-2 pr-3 text-xs">{nameOf(u.created_by)}</td>
                      <td className="py-2 pr-3"><Badge tone={u.is_active ? 'good' : 'bad'}>{u.is_active ? 'active' : 'disabled'}</Badge></td>
                      <td className="py-2 text-right">
                        {u.id !== me?.id && (
                          <Button variant="secondary" loading={toggle.isPending && toggle.variables?.id === u.id}
                            onClick={() => toggle.mutate({ id: u.id, active: !u.is_active })}>
                            {u.is_active ? 'Deactivate' : 'Activate'}
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
