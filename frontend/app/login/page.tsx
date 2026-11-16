'use client'

import { FormEvent, useState } from 'react'
import { useRouter } from 'next/navigation'
import { ShieldCheck, ArrowRight } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/lib/auth-context'

export default function LoginPage() {
  const { login, signup } = useAuth()
  const router = useRouter()
  const [mode, setMode] = useState<'login' | 'signup'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [pending, setPending] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    try {
      if (mode === 'login') await login({ email, password })
      else await signup({ email, password, full_name: name })
      router.replace('/')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Authentication failed')
    } finally { setPending(false) }
  }

  return <main className="flex min-h-screen items-center justify-center bg-[#070b12] px-4 text-slate-200"><div className="w-full max-w-md"><div className="mb-8 flex items-center justify-center gap-3"><div className="flex size-10 items-center justify-center rounded-xl bg-cyan-300 text-slate-950"><ShieldCheck className="size-6" /></div><span className="text-xl font-semibold text-white">Phish<span className="text-cyan-300">Guard</span></span></div><div className="rounded-2xl border border-white/10 bg-white/[0.035] p-6 shadow-2xl shadow-black/30 sm:p-8"><p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">Security console</p><h1 className="mt-3 text-2xl font-semibold text-white">{mode === 'login' ? 'Welcome back' : 'Create your account'}</h1><p className="mt-2 text-sm text-slate-500">{mode === 'login' ? 'Sign in to continue protecting your team.' : 'Start analyzing suspicious links with PhishGuard.'}</p><form onSubmit={submit} className="mt-7 space-y-4">{mode === 'signup' && <label className="block text-sm text-slate-400">Full name<input value={name} onChange={(event) => setName(event.target.value)} required className="mt-2 h-11 w-full rounded-xl border border-white/10 bg-black/20 px-3 text-white outline-none focus:border-cyan-300/60" /></label>}<label className="block text-sm text-slate-400">Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required className="mt-2 h-11 w-full rounded-xl border border-white/10 bg-black/20 px-3 text-white outline-none focus:border-cyan-300/60" /></label><label className="block text-sm text-slate-400">Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} required minLength={8} className="mt-2 h-11 w-full rounded-xl border border-white/10 bg-black/20 px-3 text-white outline-none focus:border-cyan-300/60" /></label><Button type="submit" disabled={pending} className="h-11 w-full rounded-xl bg-cyan-300 font-semibold text-slate-950 hover:bg-cyan-200">{pending ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}<ArrowRight className="ml-2 size-4" /></Button></form><button onClick={() => setMode(mode === 'login' ? 'signup' : 'login')} className="mt-6 w-full text-center text-sm text-slate-500 hover:text-cyan-300">{mode === 'login' ? 'Need an account? Create one' : 'Already have an account? Sign in'}</button></div></div></main>
}

