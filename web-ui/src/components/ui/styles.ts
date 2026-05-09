type ButtonVariant = 'default' | 'primary' | 'danger' | 'ghost'

type ButtonSize = 'sm' | 'md'

export function buttonClass({
  variant = 'default',
  size = 'md',
}: {
  variant?: ButtonVariant
  size?: ButtonSize
} = {}) {
  const base =
    'inline-flex items-center justify-center gap-2 rounded-lg font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500/60 disabled:opacity-50 disabled:cursor-not-allowed'

  const sizes: Record<ButtonSize, string> = {
    sm: 'px-3 py-2 text-xs',
    md: 'px-3 py-2 text-sm',
  }

  const variants: Record<ButtonVariant, string> = {
    default: 'border border-slate-800 bg-slate-900/40 text-slate-200 hover:bg-slate-800/60',
    primary: 'bg-sky-600 text-white hover:bg-sky-500',
    danger: 'bg-red-600 text-white hover:bg-red-500',
    ghost: 'text-slate-200 hover:bg-slate-900/50',
  }

  return [base, sizes[size], variants[variant]].join(' ')
}

export function panelClass({ padded = true }: { padded?: boolean } = {}) {
  return [
    'rounded-xl border border-slate-800/80 bg-slate-900/40',
    padded ? 'p-4' : '',
  ]
    .filter(Boolean)
    .join(' ')
}

export function inputClass() {
  return [
    'w-full rounded-lg border border-slate-800 bg-slate-950/30 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600',
    'focus:border-slate-700 focus:outline-none focus:ring-2 focus:ring-sky-500/30',
  ].join(' ')
}

export function selectClass() {
  return [
    'rounded-lg border border-slate-800 bg-slate-950/30 px-3 py-2 text-sm text-slate-200',
    'focus:border-slate-700 focus:outline-none focus:ring-2 focus:ring-sky-500/30',
  ].join(' ')
}

export function tableShellClass() {
  return 'overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40'
}
