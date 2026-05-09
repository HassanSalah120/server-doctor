import type { Finding, ServiceHealthItem } from '../../services/api'

export const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const

export function severityRank(severity: string): number {
  const normalized = severity.trim().toLowerCase()
  const idx = severityOrder.indexOf(normalized as (typeof severityOrder)[number])
  return idx === -1 ? severityOrder.length : idx
}

export function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, value))
}

export function groupBySeverity(findings: Finding[]): Record<string, Finding[]> {
  return findings.reduce<Record<string, Finding[]>>((acc, finding) => {
    const key = (finding.severity || 'info').toLowerCase()
    const current = acc[key] ?? []
    current.push(finding)
    acc[key] = current
    return acc
  }, {})
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

export function asArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : []
}

export function asUnknownArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

export function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null
}

export function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

export function asBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null
}

export function normalizedServiceState(state: string | undefined | null, subState: string | undefined | null): string {
  const raw = (subState || state || 'unknown').toString().trim().toLowerCase()
  return raw || 'unknown'
}

export function serviceStateTextClass(state: string): string {
  if (state === 'running' || state === 'active' || state === 'listening') return 'text-green-400'
  if (state === 'exited' || state === 'inactive') return 'text-slate-400'
  if (state === 'failed' || state === 'dead') return 'text-red-400'
  return 'text-yellow-400'
}

export function serviceStateDotClass(state: string): string {
  if (state === 'running' || state === 'active' || state === 'listening') return 'bg-green-500'
  if (state === 'exited' || state === 'inactive') return 'bg-slate-500'
  if (state === 'failed' || state === 'dead') return 'bg-red-500'
  return 'bg-yellow-500'
}

export function sortServiceHealthRows(rows: ServiceHealthItem[]): ServiceHealthItem[] {
  return [...rows].sort((a, b) => {
    const aState = normalizedServiceState(a.state, a.sub_state)
    const bState = normalizedServiceState(b.state, b.sub_state)

    const aProblem = aState === 'failed' || aState === 'dead' || (a.restart_count || 0) > 0 ? 0 : 1
    const bProblem = bState === 'failed' || bState === 'dead' || (b.restart_count || 0) > 0 ? 0 : 1
    if (aProblem !== bProblem) return aProblem - bProblem

    const aDocker = a.type === 'docker' ? 0 : 1
    const bDocker = b.type === 'docker' ? 0 : 1
    if (aDocker !== bDocker) return aDocker - bDocker

    return a.name.localeCompare(b.name)
  })
}

export function uniqueCategories(findings: Finding[]): string[] {
  const values = findings
    .map((finding) => (finding.category || '').trim())
    .filter((value) => value && value !== 'unknown')

  return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b))
}

export function filterFindingsByCategory(findings: Finding[], category: string): Finding[] {
  if (category === 'all') return findings
  return findings.filter((finding) => (finding.category || '').trim() === category)
}
