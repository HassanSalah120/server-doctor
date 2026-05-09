import { PageHeader } from '../components/PageHeader'
import { panelClass } from '../components/ui/styles'

export default function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="space-y-2">
      <PageHeader title={title} subtitle="UI migration in progress." />
      <div className={panelClass() + ' text-sm text-slate-300'}>
        This page will be replaced with a real implementation that calls the existing FastAPI endpoints.
      </div>
    </div>
  )
}
