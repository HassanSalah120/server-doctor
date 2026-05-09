import type { SSLCertificate, TopologyData } from '../../../services/api'
import { CardSection, SSLCountdownBadge } from './Primitives'

interface SSLSectionProps {
  sslStatus: SSLCertificate[]
  topology: TopologyData | undefined
}

export function SSLSection({ sslStatus, topology }: SSLSectionProps) {
  const certbot = topology?.certbot || null

  if (sslStatus.length === 0 && !certbot) return null

  return (
    <CardSection
      title="SSL Certificates"
      right={
        certbot ? (
          <div className="flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${certbot.service_failed ? 'bg-red-500' : 'bg-green-500'}`} />
            <span className="text-xs text-slate-400">Certbot {certbot.service_failed ? 'failed' : 'active'}</span>
            {certbot.domains.length > 0 && (
              <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">{certbot.domains.length} domains</span>
            )}
          </div>
        ) : undefined
      }
    >
      <div className="overflow-x-auto">
        {sslStatus.length > 0 ? (
          <table className="w-full text-sm">
            <thead className="bg-slate-800/50 text-slate-400">
              <tr>
                <th className="px-4 py-2 text-left">Certificate</th>
                <th className="px-4 py-2 text-left">Issuer</th>
                <th className="px-4 py-2 text-left">Expires</th>
                <th className="px-4 py-2 text-left">Countdown</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {sslStatus.map((cert) => (
                <tr key={cert.path} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3">
                    <div className="font-mono text-xs text-slate-300">{cert.path}</div>
                    <div className="text-xs text-slate-500">{cert.subject}</div>
                    {cert.sans.length > 0 && <div className="mt-1 text-[10px] text-slate-500">SANs: {cert.sans.join(', ')}</div>}
                  </td>
                  <td className="px-4 py-3 text-slate-300">{cert.issuer}</td>
                  <td className="px-4 py-3 text-slate-300">{cert.expires_at}</td>
                  <td className="px-4 py-3">
                    <SSLCountdownBadge cert={cert} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-sm text-slate-500">No SSL certificates detected.</div>
        )}
      </div>
    </CardSection>
  )
}
