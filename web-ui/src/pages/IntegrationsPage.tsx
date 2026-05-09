import { useEffect, useState } from 'react'
import { PageHeader } from '../components/PageHeader'
import { buttonClass, inputClass, panelClass } from '../components/ui/styles'

interface NotificationConfig {
  slack?: {
    webhook_url: string
    channel?: string
    username?: string
    only_critical?: boolean
    enabled?: boolean
  }
  webhook?: {
    url: string
    headers?: Record<string, string>
    events?: string[]
    secret?: string
    enabled?: boolean
  }
  email?: {
    smtp_host: string
    smtp_port: number
    smtp_user: string
    smtp_password: string
    from_address: string
    to_addresses: string[]
    use_tls?: boolean
    enabled?: boolean
  }
}

const API_BASE = '/api'

export default function IntegrationsPage() {
  const [, setConfig] = useState<NotificationConfig>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'slack' | 'webhook' | 'email'>('slack')

  // Form states
  const [slackForm, setSlackForm] = useState({
    webhook_url: '',
    channel: '',
    username: 'server-doctor',
    only_critical: false,
    enabled: true,
  })

  const [webhookForm, setWebhookForm] = useState({
    url: '',
    headers: '',
    events: 'scan.completed,finding.critical',
    secret: '',
    enabled: true,
  })

  const [emailForm, setEmailForm] = useState({
    smtp_host: '',
    smtp_port: 587,
    smtp_user: '',
    smtp_password: '',
    from_address: '',
    to_addresses: '',
    use_tls: true,
    enabled: true,
  })

  useEffect(() => {
    loadConfig()
  }, [])

  async function refresh() {
    setError(null)
    setMessage(null)
    await loadConfig()
  }

  async function loadConfig() {
    try {
      setLoading(true)
      const response = await fetch(`${API_BASE}/notifications/config`)
      if (!response.ok) throw new Error('Failed to load config')
      const data = await response.json()
      setConfig(data)

      if (data.slack) {
        setSlackForm({
          webhook_url: data.slack.webhook_url || '',
          channel: data.slack.channel || '',
          username: data.slack.username || 'server-doctor',
          only_critical: data.slack.only_critical || false,
          enabled: data.slack.enabled !== false,
        })
      }

      if (data.webhook) {
        setWebhookForm({
          url: data.webhook.url || '',
          headers: data.webhook.headers ? JSON.stringify(data.webhook.headers, null, 2) : '',
          events: (data.webhook.events || []).join(','),
          secret: data.webhook.secret || '',
          enabled: data.webhook.enabled !== false,
        })
      }

      if (data.email) {
        setEmailForm({
          smtp_host: data.email.smtp_host || '',
          smtp_port: data.email.smtp_port || 587,
          smtp_user: data.email.smtp_user || '',
          smtp_password: data.email.smtp_password || '',
          from_address: data.email.from_address || '',
          to_addresses: (data.email.to_addresses || []).join(','),
          use_tls: data.email.use_tls !== false,
          enabled: data.email.enabled !== false,
        })
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load config')
    } finally {
      setLoading(false)
    }
  }

  async function saveSlack() {
    try {
      setSaving(true)
      const response = await fetch(`${API_BASE}/notifications/slack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(slackForm),
      })
      if (!response.ok) throw new Error('Failed to save Slack config')
      setMessage('Slack configuration saved')
      loadConfig()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  async function saveWebhook() {
    try {
      setSaving(true)
      const payload = {
        ...webhookForm,
        headers: webhookForm.headers ? JSON.parse(webhookForm.headers) : {},
        events: webhookForm.events.split(',').map(e => e.trim()),
      }
      const response = await fetch(`${API_BASE}/notifications/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!response.ok) throw new Error('Failed to save webhook config')
      setMessage('Webhook configuration saved')
      loadConfig()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  async function saveEmail() {
    try {
      setSaving(true)
      const payload = {
        ...emailForm,
        to_addresses: emailForm.to_addresses.split(',').map(e => e.trim()),
      }
      const response = await fetch(`${API_BASE}/notifications/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!response.ok) throw new Error('Failed to save email config')
      setMessage('Email configuration saved')
      loadConfig()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  async function testNotification(channel: string) {
    try {
      const response = await fetch(`${API_BASE}/notifications/test/${channel}`, {
        method: 'POST',
      })
      if (!response.ok) throw new Error('Test failed')
      const data = await response.json()
      setMessage(data.message || `Test ${data.success ? 'successful' : 'failed'}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed')
    }
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-slate-400">Loading...</div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Integrations"
        subtitle="Configure notifications and alerts"
        actions={
          <button
            type="button"
            onClick={refresh}
            className={buttonClass({ variant: 'default', size: 'sm' })}
          >
            Refresh
          </button>
        }
      />

      {message && (
        <div className="rounded-lg border border-green-800 bg-green-950/30 p-3 text-green-400">
          <div className="flex items-start justify-between gap-3">
            <div>{message}</div>
            <button type="button" onClick={() => setMessage(null)} className="text-green-300/80 hover:text-green-200">
              Dismiss
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-red-400">
          <div className="flex items-start justify-between gap-3">
            <div>{error}</div>
            <button type="button" onClick={() => setError(null)} className="text-red-300/80 hover:text-red-200">
              Dismiss
            </button>
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-2">
        {(['slack', 'webhook', 'email'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={
              buttonClass({ variant: activeTab === tab ? 'default' : 'ghost', size: 'md' }) +
              (activeTab === tab ? '' : ' text-slate-400')
            }
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {activeTab === 'slack' && (
        <div className={panelClass() + ' space-y-4'}>
          <div className="flex items-center justify-between">
            <h3 className="font-medium">Slack Notifications</h3>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={slackForm.enabled}
                onChange={e => setSlackForm({ ...slackForm, enabled: e.target.checked })}
                className="rounded border-slate-600 bg-slate-700"
              />
              Enabled
            </label>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-sm text-slate-400">Webhook URL</label>
              <input
                type="text"
                value={slackForm.webhook_url}
                onChange={e => setSlackForm({ ...slackForm, webhook_url: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="https://hooks.slack.com/services/..."
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Channel (optional)</label>
              <input
                type="text"
                value={slackForm.channel}
                onChange={e => setSlackForm({ ...slackForm, channel: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="#alerts"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Username</label>
              <input
                type="text"
                value={slackForm.username}
                onChange={e => setSlackForm({ ...slackForm, username: e.target.value })}
                className={inputClass() + ' mt-1'}
              />
            </div>
            <div className="flex items-end">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={slackForm.only_critical}
                  onChange={e => setSlackForm({ ...slackForm, only_critical: e.target.checked })}
                  className="rounded border-slate-600 bg-slate-700"
                />
                Only critical alerts
              </label>
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={saveSlack}
              disabled={saving}
              className={buttonClass({ variant: 'primary', size: 'md' })}
            >
              {saving ? 'Saving...' : 'Save Slack Config'}
            </button>
            <button
              onClick={() => testNotification('slack')}
              className={buttonClass({ variant: 'default', size: 'md' })}
            >
              Test
            </button>
          </div>
        </div>
      )}

      {activeTab === 'webhook' && (
        <div className={panelClass() + ' space-y-4'}>
          <div className="flex items-center justify-between">
            <h3 className="font-medium">Generic Webhook</h3>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={webhookForm.enabled}
                onChange={e => setWebhookForm({ ...webhookForm, enabled: e.target.checked })}
                className="rounded border-slate-600 bg-slate-700"
              />
              Enabled
            </label>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm text-slate-400">URL</label>
              <input
                type="text"
                value={webhookForm.url}
                onChange={e => setWebhookForm({ ...webhookForm, url: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="https://example.com/webhook"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Headers (JSON)</label>
              <textarea
                value={webhookForm.headers}
                onChange={e => setWebhookForm({ ...webhookForm, headers: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white font-mono"
                placeholder='{"Authorization": "Bearer token"}'
                rows={3}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Events (comma separated)</label>
              <input
                type="text"
                value={webhookForm.events}
                onChange={e => setWebhookForm({ ...webhookForm, events: e.target.value })}
                className={inputClass() + ' mt-1'}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Secret (for HMAC signature)</label>
              <input
                type="password"
                value={webhookForm.secret}
                onChange={e => setWebhookForm({ ...webhookForm, secret: e.target.value })}
                className={inputClass() + ' mt-1'}
              />
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={saveWebhook}
              disabled={saving}
              className={buttonClass({ variant: 'primary', size: 'md' })}
            >
              {saving ? 'Saving...' : 'Save Webhook Config'}
            </button>
            <button
              onClick={() => testNotification('webhook')}
              className={buttonClass({ variant: 'default', size: 'md' })}
            >
              Test
            </button>
          </div>
        </div>
      )}

      {activeTab === 'email' && (
        <div className={panelClass() + ' space-y-4'}>
          <div className="flex items-center justify-between">
            <h3 className="font-medium">Email Notifications</h3>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={emailForm.enabled}
                onChange={e => setEmailForm({ ...emailForm, enabled: e.target.checked })}
                className="rounded border-slate-600 bg-slate-700"
              />
              Enabled
            </label>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-sm text-slate-400">SMTP Host</label>
              <input
                type="text"
                value={emailForm.smtp_host}
                onChange={e => setEmailForm({ ...emailForm, smtp_host: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="smtp.gmail.com"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">SMTP Port</label>
              <input
                type="number"
                value={emailForm.smtp_port}
                onChange={e => setEmailForm({ ...emailForm, smtp_port: parseInt(e.target.value) })}
                className={inputClass() + ' mt-1'}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">SMTP User</label>
              <input
                type="text"
                value={emailForm.smtp_user}
                onChange={e => setEmailForm({ ...emailForm, smtp_user: e.target.value })}
                className={inputClass() + ' mt-1'}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">SMTP Password</label>
              <input
                type="password"
                value={emailForm.smtp_password}
                onChange={e => setEmailForm({ ...emailForm, smtp_password: e.target.value })}
                className={inputClass() + ' mt-1'}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">From Address</label>
              <input
                type="email"
                value={emailForm.from_address}
                onChange={e => setEmailForm({ ...emailForm, from_address: e.target.value })}
                className={inputClass() + ' mt-1'}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">To Addresses (comma separated)</label>
              <input
                type="text"
                value={emailForm.to_addresses}
                onChange={e => setEmailForm({ ...emailForm, to_addresses: e.target.value })}
                className={inputClass() + ' mt-1'}
                placeholder="admin@example.com, ops@example.com"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={emailForm.use_tls}
              onChange={e => setEmailForm({ ...emailForm, use_tls: e.target.checked })}
              className="rounded border-slate-600 bg-slate-700"
            />
            <span className="text-sm">Use TLS</span>
          </div>

          <div className="flex gap-2">
            <button
              onClick={saveEmail}
              disabled={saving}
              className={buttonClass({ variant: 'primary', size: 'md' })}
            >
              {saving ? 'Saving...' : 'Save Email Config'}
            </button>
            <button
              onClick={() => testNotification('email')}
              className={buttonClass({ variant: 'default', size: 'md' })}
            >
              Test
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
