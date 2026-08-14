export type Chain = 'auto' | 'ethereum' | 'base' | 'bsc' | 'solana' | 'bitcoin'
export type InputKind = 'evm-address' | 'solana-address' | 'bitcoin-address' | 'transaction' | 'mnemonic' | 'unknown'

export interface AnalysisRequest {
  input: string
  chain: Chain
  kind: InputKind
  derivationType?: string
  count?: number
}

export interface TransactionRow {
  time: string
  direction: string
  counterparty: string
  amount: string
  hash: string
  status: string
}

export interface InvestigationResult {
  target: string
  chain: string
  detectedKind: InputKind
  balance?: string | number
  transactionCount?: number
  firstActivity?: string
  latestActivity?: string
  incomingCount?: number
  outgoingCount?: number
  counterparties: string[]
  clusterAssociations: string[]
  risk: 'clear' | 'review' | 'unknown'
  status: string
  coinjoinLikelihood?: string
  ciohAssociations?: string[]
  changeAddresses?: string[]
  transactions: TransactionRow[]
  raw: unknown
  partial?: boolean
}

export interface CaseRecord {
  id: string
  name: string
  createdAt: string
  primaryTarget: string
  chain: string
  results: InvestigationResult[]
  notes: string
  graphState: { expanded: string[] }
}

export interface ApiError {
  message: string
  status?: number
}
