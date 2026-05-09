import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: string
  subtitle?: string
  eyebrow?: string
  actions?: ReactNode
}

export function PageHeader({ title, subtitle, eyebrow, actions }: PageHeaderProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        {eyebrow ? (
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">{eyebrow}</div>
        ) : null}
        <h1 className="truncate text-2xl font-semibold tracking-tight text-slate-100">{title}</h1>
        {subtitle ? <p className="mt-1 text-sm text-slate-400">{subtitle}</p> : null}
      </div>

      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}
