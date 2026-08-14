import type { AnalysisRequest, Chain, InvestigationResult, TransactionRow } from '../types'

const API_BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '')

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    })
  } catch {
    throw new Error('Backend unavailable. Start FastAPI on 127.0.0.1:8000 and try again.')
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    const detail = typeof body?.detail === 'string' ? body.detail : 'The backend rejected this request.'
    throw new Error(`${detail}${response.status ? ` (HTTP ${response.status})` : ''}`)
  }
  return body as T
}

export const api = {
  health: () => request<{ status: string }>('/health'),
  chains: () => request<{ evm: string[]; solana: string; bitcoin: string }>('/api/v1/chains'),
  derive: (mnemonic: string, derivationType = 'ethereum', count = 5) => request('/api/v1/derive', {
    method: 'POST', body: JSON.stringify({ mnemonic, derivation_type: derivationType, count }),
  }),
  evmAnalyze: (address: string, chains?: string[]) => request(`/api/v1/evm/analyze`, {
    method: 'POST', body: JSON.stringify({ address, chains }),
  }),
  solanaAnalyze: (address: string) => request('/api/v1/solana/analyze', {
    method: 'POST', body: JSON.stringify({ address }),
  }),
  bitcoinAnalyze: () => request('/api/v1/bitcoin/analyze', {
    method: 'POST', body: JSON.stringify({ run_heuristics: true }),
  }),
  heuristicCoinjoin: (transactions: unknown[]) => request('/api/v1/heuristics/coinjoin', {
    method: 'POST', body: JSON.stringify(transactions),
  }),
  heuristicCioh: (transactions: unknown[]) => request('/api/v1/heuristics/cioh', {
    method: 'POST', body: JSON.stringify(transactions),
  }),
  heuristicChange: (transactions: unknown[]) => request('/api/v1/heuristics/change', {
    method: 'POST', body: JSON.stringify(transactions),
  }),
  keylabCapabilities: () => request('/api/v1/keylab/capabilities'),
  keylabBenchmark: (payload: unknown) => request('/api/v1/keylab/benchmark', { method: 'POST', body: JSON.stringify(payload) }),
  keylabVanityJob: (payload: unknown) => request('/api/v1/keylab/vanity/jobs', { method: 'POST', body: JSON.stringify(payload) }),
  keylabJob: (id: string) => request(`/api/v1/keylab/jobs/${id}`),
  keylabCancelJob: (id: string) => request(`/api/v1/keylab/jobs/${id}`, { method: 'DELETE' }),
  keylabSynthetic: (payload: unknown) => request('/api/v1/keylab/synthetic', { method: 'POST', body: JSON.stringify(payload) }),
  keylabSplitKey: (payload: unknown) => request('/api/v1/keylab/split-key', { method: 'POST', body: JSON.stringify(payload) }),
  entropyCapabilities: () => request('/api/v1/entropy/capabilities'),
  entropyProfiles: () => request('/api/v1/entropy/profiles'),
  entropyAnalyze: (payload: unknown) => request('/api/v1/entropy/analyze', { method: 'POST', body: JSON.stringify(payload) }),
  entropyEstimate: (payload: unknown) => request('/api/v1/entropy/estimate', { method: 'POST', body: JSON.stringify(payload) }),
  entropyValidate: (payload: unknown) => request('/api/v1/entropy/patch/validate', { method: 'POST', body: JSON.stringify(payload) }),
  entropyGenerate: (payload: unknown) => request('/api/v1/entropy/lab/generate', { method: 'POST', body: JSON.stringify(payload) }),
  entropyRecover: (payload: unknown) => request('/api/v1/entropy/lab/recover', { method: 'POST', body: JSON.stringify(payload) }),
  entropyComparePatch: (payload: unknown) => request('/api/v1/entropy/lab/compare-patch', { method: 'POST', body: JSON.stringify(payload) }),
  assuranceCapabilities: () => request('/api/v1/entropy-assurance/capabilities'),
  assuranceAuditSource: (payload: unknown) => request('/api/v1/entropy-assurance/audit-source', { method: 'POST', body: JSON.stringify(payload) }),
  assuranceAuditGenerator: (payload: unknown) => request('/api/v1/entropy-assurance/audit-generator', { method: 'POST', body: JSON.stringify(payload) }),
  assuranceRuntimeProbe: (payload: unknown) => request('/api/v1/entropy-assurance/runtime-probe', { method: 'POST', body: JSON.stringify(payload) }),
  assuranceSelfAudit: (payload: unknown = {}) => request('/api/v1/entropy-assurance/self-audit', { method: 'POST', body: JSON.stringify(payload) }),
  assuranceCompare: (payload: unknown) => request('/api/v1/entropy-assurance/compare', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryCapabilities: () => request('/api/v1/wallet-recovery/capabilities'),
  walletRecoveryAnalyze: (payload: unknown) => request('/api/v1/wallet-recovery/analyze', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryIdentifyEarlyWallet: (payload: unknown) => request('/api/v1/wallet-recovery/identify-early-wallet', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryDerive: (payload: unknown) => request('/api/v1/wallet-recovery/derive', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryVerifyAddress: (payload: unknown) => request('/api/v1/wallet-recovery/verify-address', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryAnalyzeMnemonic: (payload: unknown) => request('/api/v1/wallet-recovery/analyze-mnemonic', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryAnalyzeGenerator: (payload: unknown) => request('/api/v1/wallet-recovery/analyze-generator', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryBuildPlan: (payload: unknown) => request('/api/v1/wallet-recovery/build-plan', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoverySession: (payload: unknown) => request('/api/v1/wallet-recovery/session', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryArtifactInspect: (payload: unknown) => request('/api/v1/wallet-recovery/artifact/inspect', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryArtifactVerifyPassword: (payload: unknown) => request('/api/v1/wallet-recovery/artifact/verify-password', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryGapDiscover: (payload: unknown) => request('/api/v1/wallet-recovery/extended-key/gap-discover', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryClassifyFormat: (payload: unknown) => request('/api/v1/wallet-recovery/format/classify', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoverySlip39Reconstruct: (payload: unknown) => request('/api/v1/wallet-recovery/slip39/reconstruct', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryBip388Inspect: (payload: unknown) => request('/api/v1/wallet-recovery/policy/bip388/inspect', { method: 'POST', body: JSON.stringify(payload) }),
  walletRecoveryBsmsInspect: (payload: unknown) => request('/api/v1/wallet-recovery/policy/bsms/inspect', { method: 'POST', body: JSON.stringify(payload) }),
}

const asText = (value: unknown, fallback = 'Not available') => value === undefined || value === null || value === '' ? fallback : String(value)
const asArray = (value: unknown): unknown[] => Array.isArray(value) ? value : []

function rowsFrom(items: unknown[]): TransactionRow[] {
  return items.slice(0, 100).map((item: any) => ({
    time: asText(item?.timestamp || item?.time || item?.block_timestamp, '—'),
    direction: asText(item?.direction || item?.type, 'Unknown'),
    counterparty: asText(item?.counterparty || item?.from || item?.to, 'Not available'),
    amount: asText(item?.amount || item?.value || item?.amount_native, '—'),
    hash: asText(item?.hash || item?.tx_hash || item?.signature || item?.txid, '—'),
    status: asText(item?.status, 'Observed'),
  }))
}

export function detectInput(input: string): AnalysisRequest['kind'] {
  const trimmed = input.trim()
  const words = trimmed.split(/\s+/)
  if (words.length >= 12 && words.length <= 24) return 'mnemonic'
  if (/^0x[a-fA-F0-9]{40}$/.test(trimmed)) return 'evm-address'
  if (/^0x[a-fA-F0-9]{64}$/.test(trimmed) || /^[a-fA-F0-9]{64}$/.test(trimmed)) return 'transaction'
  if (/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{20,90}$/.test(trimmed)) return 'bitcoin-address'
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(trimmed)) return 'solana-address'
  return 'unknown'
}

export function normalizeEvm(raw: any, target: string, selected: Chain, kind: AnalysisRequest['kind']): InvestigationResult {
  const chains = raw?.chains || {}
  const entries = Object.entries(chains) as [string, any][]
  const usable = selected !== 'auto' ? entries.filter(([key]) => key === selected) : entries
  const chosen = usable.find(([, value]) => value && !value.error) || usable[0]?.[1] || {}
  const transactions = rowsFrom(asArray(chosen.transactions))
  return {
    target, chain: usable[0]?.[0] || selected || 'EVM', detectedKind: kind,
    balance: chosen.balance, transactionCount: chosen.transaction_count ?? transactions.length,
    firstActivity: chosen.first_activity, latestActivity: chosen.latest_activity,
    incomingCount: chosen.incoming_count, outgoingCount: chosen.outgoing_count,
    counterparties: asArray(chosen.counterparties).map(String), clusterAssociations: asArray(chosen.clusters).map(String),
    risk: chosen.error ? 'unknown' : 'clear', status: chosen.error ? 'Partial response' : 'Analysis complete',
    transactions, raw, partial: entries.length > 0 && entries.some(([, value]) => value?.error),
  }
}

export function normalizeSolana(raw: any, target: string): InvestigationResult {
  const transactions = rowsFrom(asArray(raw?.transactions))
  return { target, chain: 'solana', detectedKind: 'solana-address', balance: raw?.balance_sol ?? raw?.balance_lamports,
    transactionCount: raw?.transaction_count ?? transactions.length, firstActivity: raw?.first_activity,
    latestActivity: raw?.latest_activity, incomingCount: raw?.incoming_count, outgoingCount: raw?.outgoing_count,
    counterparties: asArray(raw?.counterparties).map(String), clusterAssociations: [], risk: 'unknown',
    status: 'Analysis complete', transactions, raw }
}

export function normalizeBitcoin(raw: any, target: string): InvestigationResult {
  const report = raw?.raw_data || raw
  const coinjoins = asArray(report?.coinjoins_detected)
  const cioh = report?.common_input_ownership || {}
  const changes = asArray(report?.change_addresses).map(String)
  return { target, chain: 'bitcoin', detectedKind: 'bitcoin-address', balance: undefined,
    transactionCount: raw?.transactions_analyzed ?? 0, counterparties: [], clusterAssociations: Object.keys(cioh),
    risk: coinjoins.length || changes.length ? 'review' : 'clear', status: 'Heuristics complete',
    coinjoinLikelihood: coinjoins.length ? `${coinjoins.length} possible CoinJoin finding${coinjoins.length === 1 ? '' : 's'}` : 'No CoinJoin pattern detected',
    ciohAssociations: Object.keys(cioh), changeAddresses: changes, transactions: [], raw }
}

export async function analyze(request: AnalysisRequest): Promise<InvestigationResult> {
  if (request.kind === 'mnemonic') {
    const raw: any = await api.derive(request.input, request.derivationType || 'ethereum', request.count || 5)
    const addresses = asArray(raw?.addresses)
    return { target: 'Derived public addresses', chain: request.derivationType || 'ethereum', detectedKind: 'mnemonic',
      transactionCount: 0, counterparties: addresses.map((item: any) => `${item.path}: ${item.address}`),
      clusterAssociations: [], risk: 'clear', status: 'Local derivation complete', transactions: [], raw }
  }
  if (request.kind === 'transaction') throw new Error('Transaction hashes are recognized, but no transaction lookup endpoint is exposed by the current backend.')
  if (request.kind === 'evm-address') return normalizeEvm(await api.evmAnalyze(request.input, request.chain === 'auto' ? undefined : [request.chain]), request.input, request.chain, request.kind)
  if (request.kind === 'solana-address') return normalizeSolana(await api.solanaAnalyze(request.input), request.input)
  if (request.kind === 'bitcoin-address') return normalizeBitcoin(await api.bitcoinAnalyze(), request.input)
  throw new Error('Could not identify this input. Select a chain or provide a valid address or BIP39 mnemonic.')
}
