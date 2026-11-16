import { apiRequest } from './client'
import type {
  AgentChatRequest,
  AgentChatResponse,
  AlertConfig,
  AlertConfigCreate,
  ApiKey,
  ApiKeyCreate,
  BulkScanRequest,
  BulkScanResponse,
  CheckoutRequest,
  CheckoutResponse,
  DashboardStats,
  EmailScanResponse,
  HistoryItem,
  LoginPayload,
  PlansResponse,
  ScanRequest,
  ScanResult,
  SignupPayload,
  TeamHistoryItem,
  Token,
  User,
} from './types'

export const authApi = {
  signup: (payload: SignupPayload) =>
    apiRequest<User>('/auth/signup', { method: 'POST', body: payload, anonymous: true }),
  login: (payload: LoginPayload) =>
    apiRequest<Token>('/auth/login', { method: 'POST', body: payload, anonymous: true }),
  me: () => apiRequest<User>('/auth/me'),
}

export const scanApi = {
  scanUrl: (payload: ScanRequest) =>
    apiRequest<ScanResult>('/scan', { method: 'POST', body: payload }),
  scanBulk: (payload: BulkScanRequest) =>
    apiRequest<BulkScanResponse>('/scan/bulk', { method: 'POST', body: payload }),
  publicDemo: (payload: ScanRequest) =>
    apiRequest<ScanResult>('/scan/public-demo', {
      method: 'POST',
      body: payload,
      anonymous: true,
    }),
  scanEmail: (emailText: string) =>
    apiRequest<EmailScanResponse>('/scan/email', {
      method: 'POST',
      body: { email_text: emailText },
    }),
  scanQr: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return apiRequest<ScanResult>('/scan/qr', { method: 'POST', body: fd, form: true })
  },
}

export const historyApi = {
  list: (limit = 50) => apiRequest<HistoryItem[]>(`/history?limit=${limit}`),
  stats: () => apiRequest<DashboardStats>('/history/stats'),
}

export const agentApi = {
  chat: (payload: AgentChatRequest) =>
    apiRequest<AgentChatResponse>('/agent/chat', { method: 'POST', body: payload }),
}

export const apiKeysApi = {
  list: () => apiRequest<ApiKey[]>('/api-keys'),
  create: (payload: ApiKeyCreate) =>
    apiRequest<ApiKey>('/api-keys', { method: 'POST', body: payload }),
  revoke: (id: string) =>
    apiRequest<{ detail: string }>(`/api-keys/${id}`, { method: 'DELETE' }),
}

export const alertsApi = {
  list: () => apiRequest<AlertConfig[]>('/alerts'),
  create: (payload: AlertConfigCreate) =>
    apiRequest<{ id: string; channel: string; min_risk_score: number }>('/alerts', {
      method: 'POST',
      body: payload,
    }),
}

export const billingApi = {
  plans: () => apiRequest<PlansResponse>('/billing/plans', { anonymous: true }),
  checkout: (payload: CheckoutRequest) =>
    apiRequest<CheckoutResponse>('/billing/checkout', { method: 'POST', body: payload }),
}

export const teamApi = {
  create: (name: string) =>
    apiRequest<{ id: string; name: string }>('/team', { method: 'POST', body: { name } }),
  invite: (email: string) =>
    apiRequest<{ detail: string }>('/team/invite', { method: 'POST', body: { email } }),
  history: () => apiRequest<TeamHistoryItem[]>('/team/history'),
}
