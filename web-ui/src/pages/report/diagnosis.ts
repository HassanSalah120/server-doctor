import { asBoolean, asNumber, asString, asUnknownArray, isRecord } from './utils'

export interface DiagnosisRisk {
  severity: string
  title: string
  impact: string | null
  findingId: string | null
  fixEffort: string | null
  confidence: number | null
  isAutoFixable: boolean | null
}

export interface DiagnosisPlanItem {
  priority: number | null
  title: string
  description: string | null
  category: string | null
  effort: string | null
  phase: number | null
  estimatedTime: string | null
  requiresDowntime: boolean | null
  isAutoFixable: boolean | null
}

export interface DiagnosisViewModel {
  rootCause: string | null
  healthSummary: string | null
  confidence: number | null
  topRisks: DiagnosisRisk[]
  autoFixCandidates: string[]
  remediationPlan: DiagnosisPlanItem[]
  environmentSummary: Record<string, string | number>
  categoryBreakdown: Record<string, number>
}

function parseRisk(value: unknown): DiagnosisRisk | null {
  if (!isRecord(value)) return null

  return {
    severity: asString(value.severity) || 'info',
    title: asString(value.title) || 'Risk',
    impact: asString(value.impact),
    findingId: asString(value.finding_id),
    fixEffort: asString(value.fix_effort),
    confidence: asNumber(value.confidence),
    isAutoFixable: asBoolean(value.is_auto_fixable),
  }
}

function parsePlanItem(value: unknown): DiagnosisPlanItem | null {
  if (!isRecord(value)) return null

  return {
    priority: asNumber(value.priority),
    title: asString(value.title) || '-',
    description: asString(value.description),
    category: asString(value.category),
    effort: asString(value.effort),
    phase: asNumber(value.phase),
    estimatedTime: asString(value.estimated_time),
    requiresDowntime: asBoolean(value.requires_downtime),
    isAutoFixable: asBoolean(value.is_auto_fixable),
  }
}

function parseEnvironmentSummary(value: unknown): Record<string, string | number> {
  if (!isRecord(value)) return {}

  const result: Record<string, string | number> = {}
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw === 'string' || typeof raw === 'number') {
      result[key] = raw
    }
  }
  return result
}

function parseCategoryBreakdown(value: unknown): Record<string, number> {
  if (!isRecord(value)) return {}

  const result: Record<string, number> = {}
  for (const [key, raw] of Object.entries(value)) {
    const parsed = asNumber(raw)
    if (parsed !== null) {
      result[key] = parsed
    }
  }
  return result
}

export function parseDiagnosis(value: unknown): DiagnosisViewModel | null {
  if (!isRecord(value)) return null

  return {
    rootCause: asString(value.root_cause),
    healthSummary: asString(value.health_summary),
    confidence: asNumber(value.confidence),
    topRisks: asUnknownArray(value.top_risks).map(parseRisk).filter((item): item is DiagnosisRisk => item !== null),
    autoFixCandidates: asUnknownArray(value.auto_fix_candidates)
      .map((item) => asString(item))
      .filter((item): item is string => item !== null),
    remediationPlan: asUnknownArray(value.remediation_plan)
      .map(parsePlanItem)
      .filter((item): item is DiagnosisPlanItem => item !== null),
    environmentSummary: parseEnvironmentSummary(value.environment_summary),
    categoryBreakdown: parseCategoryBreakdown(value.category_breakdown),
  }
}
