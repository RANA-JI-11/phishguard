'use client'

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { usePathname, useRouter } from 'next/navigation'
import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { clearToken, getToken, setToken } from '@/lib/api/client'
import { authApi } from '@/lib/api/services'
import type { LoginPayload, SignupPayload, User } from '@/lib/api/types'

interface AuthContextValue {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (payload: LoginPayload) => Promise<void>
  signup: (payload: SignupPayload) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient()
  const router = useRouter()
  const pathname = usePathname()
  const [hasToken, setHasToken] = useState(false)
  const [hydrated, setHydrated] = useState(false)

  useEffect(() => {
    setHasToken(!!getToken())
    setHydrated(true)
  }, [])

  const { data: user, isLoading } = useQuery({
    queryKey: ['auth', 'me'],
    queryFn: authApi.me,
    enabled: hydrated && hasToken,
    retry: false,
    staleTime: 60_000,
  })

  const login = useCallback(
    async (payload: LoginPayload) => {
      const { access_token } = await authApi.login(payload)
      setToken(access_token)
      setHasToken(true)
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
    },
    [queryClient],
  )

  const signup = useCallback(
    async (payload: SignupPayload) => {
      await authApi.signup(payload)
      const { access_token } = await authApi.login({
        email: payload.email,
        password: payload.password,
      })
      setToken(access_token)
      setHasToken(true)
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
    },
    [queryClient],
  )

  const logout = useCallback(() => {
    clearToken()
    setHasToken(false)
    queryClient.clear()
    router.push('/login')
  }, [queryClient, router])

  // If a request cleared the token underneath us (401), reflect that.
  useEffect(() => {
    if (hydrated && hasToken && !getToken()) {
      setHasToken(false)
    }
  }, [hydrated, hasToken, pathname])

  return (
    <AuthContext.Provider
      value={{
        user: user ?? null,
        isLoading: !hydrated || (hasToken && isLoading),
        isAuthenticated: hasToken && !!user,
        login,
        signup,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
