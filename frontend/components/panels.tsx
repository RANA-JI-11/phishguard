'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import jsQR from 'jsqr'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Camera, CameraOff, CheckCircle2, Copy, ImageUp, KeyRound, Mail, Plus, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { apiKeysApi, scanApi } from '@/lib/api/services'
import { API_BASE_URL } from '@/lib/api/client'
import type { ScanResult, Verdict } from '@/lib/api/types'

const card = 'rounded-2xl border border-white/10 bg-white/[0.035] p-5 sm:p-6'

function Badge({ verdict }: { verdict: Verdict }) {
  const m =
    verdict === 'safe'
      ? { t: 'Safe', Icon: CheckCircle2, c: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20' }
      : verdict === 'suspicious'
        ? { t: 'Suspicious', Icon: AlertTriangle, c: 'text-amber-300 bg-amber-300/10 border-amber-300/20' }
        : { t: 'Phishing', Icon: XCircle, c: 'text-rose-400 bg-rose-400/10 border-rose-400/20' }
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${m.c}`}>
      <m.Icon className="size-3.5" />
      {m.t}
    </span>
  )
}

function Row({ r }: { r: ScanResult }) {
  return (
    <div className="rounded-xl border border-white/5 bg-black/10 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="min-w-0 flex-1 truncate text-sm text-slate-200">{r.url}</p>
        <div className="flex items-center gap-3">
          <span className="text-sm text-slate-400">{Math.round(r.risk_score)}/100</span>
          <Badge verdict={r.verdict} />
        </div>
      </div>
      {r.risk_factors?.length ? (
        <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-slate-400">
          {r.risk_factors.slice(0, 4).map((f, i) => (
            <li key={i}>{f}</li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}

export function EmailScanner() {
  const [text, setText] = useState('')
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => scanApi.scanEmail(text),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['history'] })
      toast.success(data.urls_found ? `${data.urls_found} link(s) scanned` : 'No links found in this email')
    },
    onError: (e: Error) => toast.error(e.message || 'Unable to scan email'),
  })
  const data = mutation.data
  return (
    <>
      <section className={card}>
        <div className="mb-4 flex items-center gap-3">
          <div className="rounded-lg bg-cyan-300/10 p-2">
            <Mail className="size-4 text-cyan-300" />
          </div>
          <div>
            <h2 className="font-semibold text-white">Scan a suspicious email</h2>
            <p className="text-sm text-slate-500">Paste the full email text. Every link inside is checked.</p>
          </div>
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={8}
          placeholder={'Dear customer, your account is suspended.\nVerify now: http://sbi-kyc-update.in/login'}
          className="w-full rounded-xl border border-white/10 bg-black/20 p-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-cyan-300/60"
        />
        <Button
          type="button"
          disabled={!text.trim() || mutation.isPending}
          onClick={() => mutation.mutate()}
          className="mt-3 h-11 rounded-xl bg-cyan-300 px-6 font-semibold text-slate-950 hover:bg-cyan-200"
        >
          {mutation.isPending ? 'Scanning…' : 'Scan email'}
        </Button>
      </section>
      {data && (
        <section className={card}>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <h2 className="font-semibold text-white">
              {data.urls_found} link{data.urls_found === 1 ? '' : 's'} found
            </h2>
            {data.overall_verdict && (
              <div className="flex items-center gap-2 text-sm text-slate-400">
                Overall: <Badge verdict={data.overall_verdict} />
              </div>
            )}
          </div>
          <div className="space-y-2">
            {data.results.length ? (
              data.results.map((r, i) => <Row key={i} r={r} />)
            ) : (
              <p className="py-6 text-center text-sm text-slate-500">
                No http/https links were found in the text you pasted.
              </p>
            )}
          </div>
        </section>
      )}
    </>
  )
}

export function ApiAccess() {
  const queryClient = useQueryClient()
  const { data: keys = [], isLoading } = useQuery({ queryKey: ['api-keys'], queryFn: apiKeysApi.list })
  const create = useMutation({
    mutationFn: () => apiKeysApi.create({ label: 'dashboard' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
      toast.success('API key created')
    },
    onError: (e: Error) => toast.error(e.message),
  })
  const copy = (key: string) => {
    navigator.clipboard?.writeText(key).then(() => toast.success('Copied'), () => toast.error('Copy failed'))
  }
  return (
    <section className={card}>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-cyan-300/10 p-2">
            <KeyRound className="size-4 text-cyan-300" />
          </div>
          <div>
            <h2 className="font-semibold text-white">API keys</h2>
            <p className="text-sm text-slate-500">Use with header X-API-Key on POST /scan.</p>
          </div>
        </div>
        <Button
          type="button"
          disabled={create.isPending}
          onClick={() => create.mutate()}
          className="h-10 rounded-xl bg-cyan-300 px-4 font-semibold text-slate-950 hover:bg-cyan-200"
        >
          <Plus className="mr-1 size-4" />
          New key
        </Button>
      </div>
      <div className="mb-5 rounded-xl border border-cyan-300/15 bg-cyan-300/[0.04] p-4 text-sm leading-6 text-slate-300">
        <p className="font-medium text-white">API key kis kaam aati hai?</p>
        <p className="mt-1 text-slate-400">
          Is key se koi bhi program (aapki website, mobile app, script, Chrome extension) bina login kiye PhishGuard se URL scan karwa sakta hai. Har request ke saath header <code className="rounded bg-black/30 px-1">X-API-Key</code> bhejna hota hai. Scans aapke plan ki daily limit mein ginte hain.
        </p>
        <p className="mt-3 text-xs text-slate-500">Example (PowerShell):</p>
        <pre className="mt-1 overflow-x-auto rounded-lg bg-black/40 p-3 text-xs text-slate-300">{`Invoke-RestMethod -Method Post -Uri ${API_BASE_URL}/scan \
  -ContentType "application/json" \
  -Headers @{ "X-API-Key" = "${keys[0]?.key ?? 'YOUR_KEY'}" } \
  -Body '{"url":"http://paypa1-secure-login.xyz"}'`}</pre>
        <p className="mt-2 text-xs text-slate-500">Key kisi ko share mat karo. Leak ho jaye to nayi key banao.</p>
      </div>
      <div className="mb-4 rounded-xl border border-white/5 bg-black/20 p-4 text-xs leading-6 text-slate-400">
        <p className="mb-2 font-medium text-slate-300">What is this for?</p>
        <p>An API key lets your own app, script or website scan links with PhishGuard without logging in. Free plan: 50 scans per day.</p>
        <pre className="mt-3 overflow-x-auto rounded-lg bg-black/40 p-3 font-mono text-[11px] text-cyan-200">{'curl -X POST http://127.0.0.1:8000/scan -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" -d \'{"url":"http://paypa1-secure-login.xyz"}\''}</pre>
      </div>
      <div className="space-y-2">
        {isLoading ? (
          <p className="py-6 text-center text-sm text-slate-500">Loading…</p>
        ) : keys.length ? (
          keys.map((k) => (
            <div key={k.id} className="flex items-center justify-between gap-3 rounded-xl border border-white/5 bg-black/10 p-4">
              <div className="min-w-0">
                <p className="text-xs text-slate-500">{k.label}</p>
                <p className="truncate font-mono text-sm text-slate-200">{k.key}</p>
              </div>
              <Button type="button" variant="ghost" size="icon" onClick={() => copy(k.key)} aria-label="Copy key" className="text-slate-400 hover:text-white">
                <Copy className="size-4" />
              </Button>
            </div>
          ))
        ) : (
          <p className="py-6 text-center text-sm text-slate-500">No API keys yet.</p>
        )}
      </div>
    </section>
  )
}

export function QrScanner() {
  const videoRef = useRef<HTMLVideoElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const rafRef = useRef<number | null>(null)
  const [cameraOn, setCameraOn] = useState(false)
  const [decoded, setDecoded] = useState<string | null>(null)
  const [camError, setCamError] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const scan = useMutation({
    mutationFn: (url: string) => scanApi.scanUrl({ url }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['history'] }),
    onError: (e: Error) => toast.error(e.message || 'Unable to scan link'),
  })

  const stopCamera = useCallback(() => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current)
    rafRef.current = null
    streamRef.current?.getTracks().forEach((t) => t.stop())
    streamRef.current = null
    setCameraOn(false)
  }, [])

  useEffect(() => stopCamera, [stopCamera])

  const handleDecoded = useCallback(
    (text: string) => {
      setDecoded(text)
      if (/^https?:\/\//i.test(text.trim())) scan.mutate(text.trim())
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  )

  const tick = useCallback(() => {
    const video = videoRef.current
    const canvas = canvasRef.current
    if (!video || !canvas || video.readyState < 2) {
      rafRef.current = requestAnimationFrame(tick)
      return
    }
    canvas.width = video.videoWidth
    canvas.height = video.videoHeight
    const ctx = canvas.getContext('2d', { willReadFrequently: true })
    if (ctx) {
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height)
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height)
      const code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' })
      if (code?.data) {
        stopCamera()
        handleDecoded(code.data)
        return
      }
    }
    rafRef.current = requestAnimationFrame(tick)
  }, [handleDecoded, stopCamera])

  async function startCamera() {
    setCamError(null)
    setDecoded(null)
    scan.reset()
    if (!navigator.mediaDevices?.getUserMedia) {
      setCamError('Camera is not available here. Open the app at http://localhost:3000 (not the network IP) in Chrome.')
      return
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
      streamRef.current = stream
      setCameraOn(true)
      requestAnimationFrame(() => {
        const v = videoRef.current
        if (v) {
          v.srcObject = stream
          v.play().catch(() => {})
          rafRef.current = requestAnimationFrame(tick)
        }
      })
    } catch (err) {
      const name = (err as DOMException)?.name
      setCamError(
        name === 'NotAllowedError'
          ? 'Camera permission was blocked. Click the camera icon in the address bar, allow it, then try again.'
          : name === 'NotFoundError'
            ? 'No camera was found on this device. Use "Upload QR image" instead.'
            : 'Could not start the camera. Close other apps using it, or use "Upload QR image".',
      )
    }
  }

  function onFile(file: File | undefined) {
    if (!file) return
    setCamError(null)
    setDecoded(null)
    scan.reset()
    const url = URL.createObjectURL(file)
    const img = new Image()
    img.onload = () => {
      const canvas = canvasRef.current
      const ctx = canvas?.getContext('2d', { willReadFrequently: true })
      if (!canvas || !ctx) return
      const max = 1200
      const ratio = Math.min(1, max / Math.max(img.width, img.height))
      canvas.width = Math.round(img.width * ratio)
      canvas.height = Math.round(img.height * ratio)
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
      const data = ctx.getImageData(0, 0, canvas.width, canvas.height)
      const code = jsQR(data.data, data.width, data.height, { inversionAttempts: 'attemptBoth' })
      URL.revokeObjectURL(url)
      if (code?.data) handleDecoded(code.data)
      else toast.error('No QR code found in this image. Try a sharper, closer photo.')
    }
    img.onerror = () => {
      URL.revokeObjectURL(url)
      toast.error('Could not read this image file.')
    }
    img.src = url
  }

  const result = scan.data
  const isLink = decoded ? /^https?:\/\//i.test(decoded.trim()) : false

  return (
    <>
      <section className={card}>
        <div className="mb-4 flex items-center gap-3">
          <div className="rounded-lg bg-cyan-300/10 p-2">
            <Camera className="size-4 text-cyan-300" />
          </div>
          <div>
            <h2 className="font-semibold text-white">QR code scanner</h2>
            <p className="text-sm text-slate-500">QR ka link kholne se pehle check karo. Link apne aap open nahi hota.</p>
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          {!cameraOn ? (
            <Button type="button" onClick={startCamera} className="h-11 rounded-xl bg-cyan-300 px-5 font-semibold text-slate-950 hover:bg-cyan-200">
              <Camera className="mr-2 size-4" />
              Start camera
            </Button>
          ) : (
            <Button type="button" onClick={stopCamera} className="h-11 rounded-xl bg-rose-400 px-5 font-semibold text-slate-950 hover:bg-rose-300">
              <CameraOff className="mr-2 size-4" />
              Stop camera
            </Button>
          )}
          <label className="inline-flex h-11 cursor-pointer items-center rounded-xl border border-white/10 px-5 text-sm font-medium text-slate-200 hover:bg-white/5">
            <ImageUp className="mr-2 size-4" />
            Upload QR image
            <input type="file" accept="image/*" className="hidden" onChange={(e) => { onFile(e.target.files?.[0]); e.target.value = '' }} />
          </label>
        </div>

        {camError && <p className="mt-4 rounded-xl border border-rose-400/20 bg-rose-400/10 p-3 text-sm text-rose-300">{camError}</p>}

        <div className={cameraOn ? 'mt-4 overflow-hidden rounded-xl border border-white/10 bg-black' : 'hidden'}>
          <video ref={videoRef} playsInline muted className="max-h-[420px] w-full object-contain" />
        </div>
        <canvas ref={canvasRef} className="hidden" />
        {cameraOn && <p className="mt-2 text-xs text-slate-500">QR ko camera ke saamne seedha aur roshni mein rakho. Detect hote hi apne aap scan ho jayega.</p>}
      </section>

      {decoded && (
        <section className={card}>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">QR ke andar likha hai</p>
          <p className="mt-1 break-all font-mono text-sm text-white">{decoded}</p>
          {!isLink && <p className="mt-3 text-sm text-amber-300">Yeh http/https link nahi hai (shayad text, WiFi ya payment data). Isliye URL check nahi hua.</p>}
          {scan.isPending && <p className="mt-3 text-sm text-slate-400">Link check ho raha hai…</p>}
          {result && (
            <div className="mt-4">
              <Row r={result} />
              {result.ai_explanation && <p className="mt-3 text-sm leading-6 text-slate-400">{result.ai_explanation}</p>}
            </div>
          )}
        </section>
      )}
    </>
  )
}
