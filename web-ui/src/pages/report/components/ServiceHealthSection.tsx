import type { ServiceHealthItem } from '../../../services/api'
import { normalizedServiceState, serviceStateDotClass, serviceStateTextClass } from '../utils'
import { CardSection } from './Primitives'

interface ServiceHealthSectionProps {
  rows: ServiceHealthItem[]
}

export function ServiceHealthSection({ rows }: ServiceHealthSectionProps) {
  if (rows.length === 0) return null

  return (
    <CardSection title="Service Health">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-slate-800/50 text-slate-400">
            <tr>
              <th className="px-4 py-2 text-left">Service</th>
              <th className="px-4 py-2 text-left">Status</th>
              <th className="px-4 py-2 text-left">Restarts</th>
              <th className="px-4 py-2 text-left">Ports</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.map((service) => {
              const state = normalizedServiceState(service.state, service.sub_state)
              const ports = Array.isArray(service.ports) ? service.ports : []

              return (
                <tr key={`${service.name}-${service.type || 'system'}`} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className={`h-2 w-2 rounded-full ${serviceStateDotClass(state)}`} />
                      <span className="font-medium text-slate-200">{service.name}</span>
                      {service.type === 'docker' && (
                        <span className="rounded bg-blue-500/20 px-1.5 py-0.5 text-[10px] text-blue-400">docker</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs ${serviceStateTextClass(state)}`}>{state}</span>
                  </td>
                  <td className="px-4 py-3">
                    {service.restart_count > 0 ? (
                      <span className="text-xs text-yellow-400">{service.restart_count} restarts</span>
                    ) : (
                      <span className="text-xs text-slate-500">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {ports.slice(0, 3).map((port) => (
                        <span key={`${service.name}-${port}`} className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">
                          {port}
                        </span>
                      ))}
                      {ports.length > 3 && <span className="text-[10px] text-slate-500">+{ports.length - 3}</span>}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </CardSection>
  )
}
