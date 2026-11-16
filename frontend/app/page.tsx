'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Dashboard } from '@/components/dashboard'
import { useAuth } from '@/lib/auth-context'

export default function Page() {
  const { isAuthenticated, isLoading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!isLoading && !isAuthenticated) router.replace('/login')
  }, [isAuthenticated, isLoading, router])

  if (isLoading || !isAuthenticated) {
    return <main className="flex min-h-screen items-center justify-center bg-[#070b12] text-sm text-slate-500">Loading PhishGuard…</main>
  }

  return <Dashboard />
}
