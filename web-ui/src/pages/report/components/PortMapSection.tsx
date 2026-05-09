import type { PortMapping } from '../../../services/api'
import { CardSection } from './Primitives'

interface PortMapSectionProps {
  portMap: PortMapping[]
}

export function PortMapSection({ portMap }: PortMapSectionProps) {
  if (portMap.length === 0) return null

  return (
    <CardSection title="Port Map">
      <div className="flex flex-wrap gap-2">
        {portMap.map((port) => (
          <div key={`${port.port}-${port.service}-${port.type}`} className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950/30 px-3 py-2 transition-colors hover:border-slate-700">
            <span className="text-lg font-bold text-slate-200">{port.port}</span>
            <div className="flex flex-col">
              <span className="text-xs text-slate-300">{port.service}</span>
              <span className="text-[10px] text-slate-500">{port.type}</span>
            </div>
            {port.container_port && (
              <span className="ml-1 rounded bg-blue-500/20 px-1.5 py-0.5 text-[10px] text-blue-400">to {port.container_port}</span>
            )}
          </div>
        ))}
      </div>
    </CardSection>
  )
}
