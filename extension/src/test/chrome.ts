// Minimal in-memory chrome.storage for tests.

type Area = {
  data: Record<string, unknown>
  get: (keys?: string | string[] | null) => Promise<Record<string, unknown>>
  set: (items: Record<string, unknown>) => Promise<void>
  remove: (keys: string | string[]) => Promise<void>
}

function area(initial: Record<string, unknown> = {}, fail = false): Area {
  const a: Area = {
    data: { ...initial },
    get: async (keys) => {
      if (fail) throw new Error('managed storage unavailable')
      if (keys === null || keys === undefined) return { ...a.data }
      const list = typeof keys === 'string' ? [keys] : keys
      return Object.fromEntries(list.filter((k) => k in a.data).map((k) => [k, a.data[k]]))
    },
    set: async (items) => {
      Object.assign(a.data, items)
    },
    remove: async (keys) => {
      for (const k of typeof keys === 'string' ? [keys] : keys) delete a.data[k]
    },
  }
  return a
}

export function installChrome(opts: { local?: Record<string, unknown>; managed?: Record<string, unknown> | 'none' } = {}) {
  const storage = {
    local: area(opts.local),
    session: area(),
    managed: opts.managed === 'none' || opts.managed === undefined ? area({}, opts.managed === 'none') : area(opts.managed),
  }
  ;(globalThis as unknown as { chrome: unknown }).chrome = { storage }
  return storage
}
