// Thin fetch wrapper around the PhishGuard FastAPI backend.
// Base URL comes from NEXT_PUBLIC_API_BASE_URL (set it to your deployed API).

export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'
).replace(/\/$/, '')

const TOKEN_KEY = 'phishguard_token'

export function getToken(): string | null {
  if (typeof window === 'undefined') return null
  return window.localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  if (typeof window === 'undefined') return
  window.localStorage.removeItem(TOKEN_KEY)
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function extractDetail(body: unknown, fallback: string): string {
  if (!body || typeof body !== 'object') return fallback
  const detail = (body as { detail?: unknown }).detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    const first = detail[0] as { msg?: string } | undefined
    if (first?.msg) return first.msg
  }
  return fallback
}

interface RequestOptions {
  method?: string
  body?: unknown
  /** Skip the Authorization header (public endpoints). */
  anonymous?: boolean
  /** When true, `body` is sent as-is (FormData) without JSON serialization. */
  form?: boolean
  signal?: AbortSignal
}

export async function apiRequest<T>(
  path: string,
  { method = 'GET', body, anonymous = false, form = false, signal }: RequestOptions = {},
): Promise<T> {
  const headers: Record<string, string> = {}
  const token = getToken()

  if (!anonymous && token) {
    headers.Authorization = `Bearer ${token}`
  }

  let payload: BodyInit | undefined
  if (body !== undefined) {
    if (form) {
      payload = body as BodyInit
    } else {
      headers['Content-Type'] = 'application/json'
      payload = JSON.stringify(body)
    }
  }

  let res: Response
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      method,
      headers,
      body: payload,
      signal,
    })
  } catch {
    throw new ApiError(
      'Could not reach the PhishGuard API. Check that the backend is running and NEXT_PUBLIC_API_BASE_URL is set.',
      0,
    )
  }

  const isJson = res.headers.get('content-type')?.includes('application/json')
  const data = isJson ? await res.json().catch(() => null) : await res.text().catch(() => null)

  if (!res.ok) {
    if (res.status === 401 && !anonymous) {
      clearToken()
    }
    throw new ApiError(extractDetail(data, `Request failed (${res.status})`), res.status)
  }

  return data as T
}
