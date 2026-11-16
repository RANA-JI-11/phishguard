'use client'

import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ArrowUpRight, CheckCircle2, Clipboard, ExternalLink, History, Link2, LogOut, Menu, Radar, ShieldCheck, Sparkles, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { useAuth } from '@/lib/auth-context'
import { agentApi, historyApi, scanApi } from '@/lib/api/services'
import type { ScanResult, Verdict } from '@/lib/api/types'
import { ApiAccess, EmailScanner, QrScanner } from '@/components/panels'

const navItems = ['Overview', 'URL Scanner', 'Email Scanner', 'QR Scanner', 'History', 'API Access']

function verdictMeta(verdict: Verdict) {
  return verdict === 'safe'
    ? { label: 'Safe', icon: CheckCircle2, className: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20' }
    : verdict === 'suspicious'
      ? { label: 'Suspicious', icon: AlertTriangle, className: 'text-amber-300 bg-amber-300/10 border-amber-300/20' }
      : { label: 'Phishing', icon: XCircle, className: 'text-rose-400 bg-rose-400/10 border-rose-400/20' }
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const meta = verdictMeta(verdict)
  const Icon = meta.icon
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${meta.className}`}><Icon className="size-3.5" />{meta.label}</span>
}

function ScanCard({ onResult }: { onResult: (result: ScanResult) => void }) {
  const [url, setUrl] = useState('')
  const mutation = useMutation({
    mutationFn: () => scanApi.scanUrl({ url }),
    onSuccess: (result) => { onResult(result); toast.success('Scan complete') },
    onError: (error: Error) => toast.error(error.message || 'Unable to scan URL'),
  })
  return <section className="rounded-2xl border border-white/10 bg-white/[0.035] p-5 shadow-2xl shadow-black/20 sm:p-6">
    <div className="mb-5 flex items-start justify-between gap-4"><div><p className="mb-1 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">Threat scanner</p><h2 className="text-xl font-semibold tracking-tight text-white">Inspect a suspicious link</h2><p className="mt-1 text-sm text-slate-400">Analyze URLs with PhishGuard&apos;s AI risk engine.</p></div><div className="hidden rounded-xl border border-cyan-300/20 bg-cyan-300/10 p-3 sm:block"><Radar className="size-5 text-cyan-300" /></div></div>
    <form onSubmit={(event) => { event.preventDefault(); if (url.trim()) mutation.mutate() }} className="flex flex-col gap-3 sm:flex-row"><div className="relative flex-1"><Link2 className="absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-slate-500" /><input value={url} onChange={(event) => setUrl(event.target.value)} type="url" required placeholder="https://example.com/login" className="h-12 w-full rounded-xl border border-white/10 bg-black/20 pl-10 pr-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-300/60 focus:ring-2 focus:ring-cyan-300/10" /></div><Button type="submit" disabled={mutation.isPending} className="h-12 rounded-xl bg-cyan-300 px-6 font-semibold text-slate-950 hover:bg-cyan-200">{mutation.isPending ? 'Analyzing…' : 'Scan URL'}<ArrowUpRight className="ml-2 size-4" /></Button></form>
  </section>
}

function ResultCard({ result }: { result: ScanResult }) {
  return <section className="rounded-2xl border border-cyan-300/20 bg-cyan-300/[0.045] p-5 sm:p-6"><div className="flex flex-wrap items-center justify-between gap-3"><div className="min-w-0"><p className="mb-1 text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Latest analysis</p><p className="truncate text-sm font-medium text-white">{result.url}</p></div><VerdictBadge verdict={result.verdict} /></div><div className="mt-6 grid gap-4 sm:grid-cols-3"><div><p className="text-xs text-slate-500">Risk score</p><p className="mt-1 text-2xl font-semibold text-white">{Math.round(result.risk_score)}<span className="text-sm text-slate-500">/100</span></p></div><div><p className="text-xs text-slate-500">ML confidence</p><p className="mt-1 text-2xl font-semibold text-white">{Math.round(result.ml_confidence)}<span className="text-sm text-slate-500">%</span></p></div><div><p className="text-xs text-slate-500">Risk factors</p><p className="mt-1 text-sm text-slate-300">{result.risk_factors?.length ? result.risk_factors.join(', ') : 'No risk factors detected'}</p></div></div><p className="mt-5 border-t border-white/10 pt-4 text-sm leading-6 text-slate-400">{result.ai_explanation}</p></section>
}

export function Dashboard() {
  const { user, logout } = useAuth()
  const queryClient = useQueryClient()
  const [active, setActive] = useState('Overview')
  const [latest, setLatest] = useState<ScanResult | null>(null)
  const [agentMessage, setAgentMessage] = useState('')
  const [agentReply, setAgentReply] = useState('')
  const { data: stats } = useQuery({ queryKey: ['history', 'stats'], queryFn: historyApi.stats })
  const { data: history = [] } = useQuery({ queryKey: ['history'], queryFn: () => historyApi.list(8) })
  const agent = useMutation({ mutationFn: agentApi.chat, onSuccess: (data) => setAgentReply(data.reply), onError: () => toast.error('Assistant unavailable') })
  const statCards = useMemo(() => [
    { label: 'Total scans', value: stats?.total_scans ?? '—', icon: Radar, color: 'text-cyan-300' },
    { label: 'Safe links', value: stats?.by_verdict?.safe ?? '—', icon: ShieldCheck, color: 'text-emerald-400' },
    { label: 'Threats caught', value: (stats?.by_verdict?.phishing ?? 0) + (stats?.by_verdict?.suspicious ?? 0), icon: AlertTriangle, color: 'text-amber-300' },
  ], [stats])
  const displayName = user?.full_name || user?.email?.split('@')[0] || 'Operator'

  const content = active === 'Email Scanner' ? <EmailScanner /> : active === 'API Access' ? <ApiAccess /> : active === 'QR Scanner' ? <QrScanner /> : active === 'History' ? <section className="rounded-2xl border border-white/10 bg-white/[0.035] p-5"><div className="mb-5 flex items-center gap-3"><History className="size-5 text-cyan-300" /><div><h2 className="font-semibold text-white">Scan history</h2><p className="text-sm text-slate-500">Your latest URL analyses</p></div></div><div className="space-y-2">{history.length ? history.map((item, index) => <div key={`${item.url}-${index}`} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/5 bg-black/10 p-4"><div className="min-w-0"><p className="truncate text-sm text-slate-200">{item.url}</p><p className="mt-1 text-xs text-slate-500">{new Date(item.created_at).toLocaleString()}</p></div><div className="flex items-center gap-3"><span className="text-sm text-slate-400">{Math.round(item.risk_score)}/100</span><VerdictBadge verdict={item.verdict} /></div></div>) : <p className="py-10 text-center text-sm text-slate-500">No scans yet.</p>}</div></section> : <><ScanCard onResult={(result) => { setLatest(result); queryClient.invalidateQueries({ queryKey: ['history'] }); queryClient.invalidateQueries({ queryKey: ['history', 'stats'] }) }} />{latest && <ResultCard result={latest} />}<section className="rounded-2xl border border-white/10 bg-white/[0.035] p-5"><div className="mb-4 flex items-center gap-3"><div className="rounded-lg bg-violet-400/10 p-2"><Sparkles className="size-4 text-violet-300" /></div><div><h2 className="font-semibold text-white">Ask the security assistant</h2><p className="text-sm text-slate-500">Get a plain-language explanation of a threat.</p></div></div><div className="flex gap-2"><input value={agentMessage} onChange={(event) => setAgentMessage(event.target.value)} placeholder="Is this link safe?" className="h-11 min-w-0 flex-1 rounded-xl border border-white/10 bg-black/20 px-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-violet-300/50" /><Button disabled={!agentMessage || agent.isPending} onClick={() => agent.mutate({ message: agentMessage })} className="h-11 rounded-xl bg-violet-400 text-slate-950 hover:bg-violet-300">Ask</Button></div>{agentReply && <p className="mt-4 rounded-xl border border-violet-300/15 bg-violet-300/5 p-4 text-sm leading-6 text-slate-300">{agentReply}</p>}</section></>

  return <div className="min-h-screen bg-[#070b12] text-slate-200"><header className="sticky top-0 z-20 border-b border-white/10 bg-[#070b12]/90 backdrop-blur-xl"><div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6"><div className="flex items-center gap-3"><Sheet><SheetTrigger render={<Button variant="ghost" size="icon" className="text-slate-400 md:hidden" />}><Menu /></SheetTrigger><SheetContent side="left" className="border-white/10 bg-[#0b111b] text-white"><nav className="mt-8 space-y-1">{navItems.map((item) => <button key={item} onClick={() => setActive(item)} className="block w-full rounded-lg px-3 py-2 text-left text-sm text-slate-300 hover:bg-white/5">{item}</button>)}</nav></SheetContent></Sheet><div className="flex size-8 items-center justify-center rounded-lg bg-cyan-300 text-slate-950"><ShieldCheck className="size-5" /></div><span className="font-semibold tracking-tight text-white">Phish<span className="text-cyan-300">Guard</span></span><span className="hidden rounded-full border border-white/10 px-2 py-0.5 text-[10px] uppercase tracking-wider text-slate-500 sm:inline">SOC console</span></div><div className="flex items-center gap-3"><div className="hidden text-right sm:block"><p className="text-sm font-medium text-white">{displayName}</p><p className="text-xs capitalize text-slate-500">{user?.plan || 'free'} plan</p></div><Button variant="ghost" size="icon" onClick={logout} aria-label="Log out" className="text-slate-400 hover:text-white"><LogOut className="size-4" /></Button></div></div></header><div className="mx-auto flex max-w-7xl"><aside className="hidden min-h-[calc(100vh-4rem)] w-56 shrink-0 border-r border-white/10 py-8 pr-5 md:block"><nav className="space-y-1">{navItems.map((item) => <button key={item} onClick={() => setActive(item)} className={`flex w-full items-center rounded-lg px-3 py-2.5 text-left text-sm transition ${active === item ? 'bg-cyan-300/10 font-medium text-cyan-200' : 'text-slate-500 hover:bg-white/5 hover:text-slate-200'}`}>{item}</button>)}</nav><div className="mt-10 rounded-xl border border-cyan-300/15 bg-cyan-300/5 p-4"><p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Protection status</p><p className="mt-2 flex items-center gap-2 text-sm text-slate-300"><span className="size-2 rounded-full bg-emerald-400 shadow-[0_0_10px] shadow-emerald-400" />Systems operational</p></div></aside><main className="min-w-0 flex-1 px-4 py-8 sm:px-8"><div className="mb-8"><p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">{active === 'Overview' ? 'Security overview' : active}</p><h1 className="text-3xl font-semibold tracking-tight text-white">Good to see you, {displayName.split(' ')[0]}.</h1><p className="mt-2 text-sm text-slate-500">Monitor links, investigate threats, and keep your team protected.</p></div>{active === 'Overview' && <div className="mb-6 grid gap-3 sm:grid-cols-3">{statCards.map(({ label, value, icon: Icon, color }) => <div key={label} className="rounded-2xl border border-white/10 bg-white/[0.035] p-4"><div className="mb-5 flex items-center justify-between"><p className="text-sm text-slate-500">{label}</p><Icon className={`size-4 ${color}`} /></div><p className="text-2xl font-semibold text-white">{value}</p><p className="mt-1 text-xs text-emerald-400">Live from your account</p></div>)}</div>}{content}</main></div></div>
}
