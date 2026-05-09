import { useMemo, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'

const primaryNavItems = [
  { to: '/', label: 'Dashboard', icon: 'dashboard' },
  { to: '/servers', label: 'Servers', icon: 'servers' },
  { to: '/jobs', label: 'Jobs', icon: 'jobs' },
  { to: '/fixes', label: 'Fix Center', icon: 'fixes' },
  { to: '/readiness', label: 'Readiness', icon: 'readiness' },
]

const platformNavItems = [
  { to: '/kubernetes', label: 'Kubernetes', icon: 'kubernetes' },
]

const settingsNavItems = [
  { to: '/settings/integrations', label: 'Integrations', icon: 'integrations' },
  { to: '/settings/daemon', label: 'Daemon', icon: 'daemon' },
]

function NavIcon({ name }: { name: string }) {
  const base = 'h-4 w-4 shrink-0'

  switch (name) {
    case 'dashboard':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 13h7V4H4v9Zm9 7h7V11h-7v9ZM4 20h7v-5H4v5Zm9-9h7V4h-7v7Z" />
        </svg>
      )
    case 'servers':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 6c0-1.1.9-2 2-2h12c1.1 0 2 .9 2 2v4c0 1.1-.9 2-2 2H6c-1.1 0-2-.9-2-2V6Z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 14c0-1.1.9-2 2-2h12c1.1 0 2 .9 2 2v4c0 1.1-.9 2-2 2H6c-1.1 0-2-.9-2-2v-4Z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M8 8h.01M8 16h.01" />
        </svg>
      )
    case 'jobs':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 6V4h6v2" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M6 6h12a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2Z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6M9 16h6" />
        </svg>
      )
    case 'kubernetes':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 2l7 4v12l-7 4-7-4V6l7-4Z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 22V12" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 6l-7 6-7-6" />
        </svg>
      )
    case 'integrations':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M10 13a5 5 0 0 1 0-7l.8-.8a5 5 0 0 1 7 7l-.8.8" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M14 11a5 5 0 0 1 0 7l-.8.8a5 5 0 0 1-7-7l.8-.8" />
        </svg>
      )
    case 'daemon':
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v3" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M18.36 5.64 16.24 7.76" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 12h-3" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M18.36 18.36 16.24 16.24" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 21v-3" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M5.64 18.36 7.76 16.24" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 12h3" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M5.64 5.64 7.76 7.76" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z" />
        </svg>
      )
    default:
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 20h9" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 4h9" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 9h16" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 15h16" />
        </svg>
      )
  }
}

function NavItem({
  to,
  label,
  icon,
  onNavigate,
}: {
  to: string
  label: string
  icon: string
  onNavigate?: () => void
}) {
  return (
    <NavLink
      to={to}
      end={to === '/'}
      onClick={onNavigate}
      className={({ isActive }) =>
        [
          'group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-semibold transition',
          isActive
            ? 'bg-slate-900/70 text-white ring-1 ring-slate-800'
            : 'text-slate-300 hover:bg-slate-900/40 hover:text-white',
        ].join(' ')
      }
    >
      {({ isActive }: { isActive: boolean }) => (
        <>
          <span
            className={[
              'absolute left-0 top-1/2 h-6 w-1 -translate-y-1/2 rounded-r',
              isActive ? 'bg-sky-400/80' : 'bg-transparent group-hover:bg-slate-700/60',
            ].join(' ')}
          />
          <span className={isActive ? 'text-sky-200' : 'text-slate-400 group-hover:text-slate-200'}>
            <NavIcon name={icon} />
          </span>
          <span className="min-w-0 flex-1 truncate">{label}</span>
        </>
      )}
    </NavLink>
  )
}

function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="flex h-full flex-col">
      <div className="mb-6 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-800 bg-slate-900/40">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-sky-200">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 4h16v16H4V4Z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M8 8h8v8H8V8Z" />
          </svg>
        </div>
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold tracking-tight text-slate-100">ServerDoctor</div>
          <div className="truncate text-xs text-slate-500">Local infrastructure diagnosis</div>
        </div>
      </div>

      <nav className="flex flex-col gap-1">
        {primaryNavItems.map((i) => (
          <NavItem key={i.to} to={i.to} label={i.label} icon={i.icon} onNavigate={onNavigate} />
        ))}

        <div className="my-4 border-t border-slate-900" />
        <div className="px-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Platform</div>
        {platformNavItems.map((i) => (
          <NavItem key={i.to} to={i.to} label={i.label} icon={i.icon} onNavigate={onNavigate} />
        ))}

        <div className="my-4 border-t border-slate-900" />
        <div className="px-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Settings</div>
        {settingsNavItems.map((i) => (
          <NavItem key={i.to} to={i.to} label={i.label} icon={i.icon} onNavigate={onNavigate} />
        ))}
      </nav>

      <div className="mt-auto pt-6 text-xs text-slate-500">
        <div className="rounded-lg border border-slate-900 bg-slate-950/40 px-3 py-2">Runs on localhost only</div>
      </div>
    </div>
  )
}

export default function AppLayout() {
  const location = useLocation()
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  const pageTitle = useMemo(() => {
    const all = [...primaryNavItems, ...platformNavItems, ...settingsNavItems]
    const exact = all.find((i) => i.to === location.pathname)
    if (exact) return exact.label

    if (location.pathname.startsWith('/reports/')) return 'Report'
    if (location.pathname.startsWith('/jobs/')) return 'Job'

    return 'AI Infrastructure Diagnosis Platform'
  }, [location.pathname])

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex min-h-screen w-full max-w-[1600px]">
        <aside className="hidden w-72 flex-col border-r border-slate-900/80 bg-slate-950/30 p-4 md:flex">
          <SidebarNav />
        </aside>

        {mobileNavOpen && (
          <div className="fixed inset-0 z-40 md:hidden">
            <button
              type="button"
              className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm"
              onClick={() => setMobileNavOpen(false)}
              aria-label="Close navigation"
            />
            <div className="absolute left-0 top-0 h-full w-80 max-w-[85vw] border-r border-slate-900 bg-slate-950 p-4 shadow-2xl">
              <div className="mb-4 flex items-center justify-between">
                <div className="text-sm font-semibold text-slate-200">Navigation</div>
                <button
                  type="button"
                  onClick={() => setMobileNavOpen(false)}
                  className="rounded-md border border-slate-800 bg-slate-900/40 px-2 py-1 text-xs font-semibold text-slate-200 hover:bg-slate-800/60"
                >
                  Close
                </button>
              </div>
              <SidebarNav onNavigate={() => setMobileNavOpen(false)} />
            </div>
          </div>
        )}

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-30 border-b border-slate-900/80 bg-slate-950/70 backdrop-blur">
            <div className="flex items-center justify-between gap-3 px-4 py-3 md:px-6">
              <div className="flex min-w-0 items-center gap-3">
                <button
                  type="button"
                  onClick={() => setMobileNavOpen(true)}
                  className="inline-flex items-center justify-center rounded-lg border border-slate-800 bg-slate-900/40 p-2 text-slate-200 hover:bg-slate-800/60 md:hidden"
                  aria-label="Open navigation"
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
                  </svg>
                </button>

                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold text-slate-100">{pageTitle}</div>
                  <div className="hidden text-xs text-slate-500 sm:block">AI Infrastructure Diagnosis Platform</div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <a
                  className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800/60"
                  href="/api/docs"
                  target="_blank"
                  rel="noreferrer"
                >
                  API Docs
                </a>
              </div>
            </div>
          </header>

          <main className="flex-1 px-4 py-6 md:px-6 2xl:px-8">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  )
}
