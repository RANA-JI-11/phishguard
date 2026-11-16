// TypeScript mirrors of the PhishGuard FastAPI schemas (app/schemas.py).
// Keep these in sync with the backend contract.

export type Verdict = 'safe' | 'suspicious' | 'phishing'
export type PlanId = 'free' | 'pro' | 'business'

export interface User {
  id: string
  email: string
  full_name: string | null
  plan: PlanId
  preferred_language: string
}

export interface Token {
  access_token: string
  token_type: string
}

export interface SignupPayload {
  email: string
  password: string
  full_name?: string
  preferred_language?: string
}

export interface LoginPayload {
  email: string
  password: string
}

export interface ScanRequest {
  url: string
  language?: string
}

export interface BulkScanRequest {
  urls: string[]
  language?: string
}

export interface ScanResult {
  url: string
  verdict: Verdict
  risk_score: number
  ml_confidence: number
  risk_factors: string[]
  ai_explanation: string
  checked_at: string
}

export interface BulkScanResponse {
  results: ScanResult[]
}

export interface EmailScanPayload {
  email_text: string
}

export interface EmailScanResponse {
  urls_found: number
  overall_verdict?: Verdict
  results: ScanResult[]
}

export interface ApiKey {
  id: string
  key: string
  label: string
  is_active: boolean
}

export interface ApiKeyCreate {
  label?: string
}

export interface HistoryItem {
  url: string
  verdict: Verdict
  risk_score: number
  ai_explanation: string
  created_at: string
}

export interface DashboardStats {
  total_scans: number
  by_verdict: Partial<Record<Verdict, number>>
  daily_trend: { date: string; count: number }[]
  plan: PlanId
}

export interface AgentChatRequest {
  message: string
  url?: string
  language?: string
}

export interface AgentChatResponse {
  reply: string
}

export interface AlertConfigCreate {
  channel: 'slack' | 'email' | 'webhook'
  target: string
  min_risk_score?: number
}

export interface AlertConfig {
  id: string
  channel: string
  target: string
  min_risk_score: number
  is_active: boolean
}

export interface PlanLimits {
  daily_scans: number
  bulk_scan: boolean
  price_inr: number
}

export type PlansResponse = Record<PlanId, PlanLimits>

export interface CheckoutRequest {
  plan: 'pro' | 'business'
}

export interface CheckoutResponse {
  checkout_url: string
}

export interface TeamCreatePayload {
  name: string
}

export interface TeamInvitePayload {
  email: string
}

export interface TeamHistoryItem {
  url: string
  verdict: Verdict
  risk_score: number
  created_at: string
}
