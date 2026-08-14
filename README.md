# Chain-Trace Tool

A local-first, zero-key cryptocurrency forensics and multi-chain exploration tool inspired by architectures like `chain-trace` and `Sherlock`. The application runs entirely offline or leverages zero-key public aggregators/RPCs without requiring commercial API keys.

## Architecture

```
chain-trace-tool/
├── backend/           # Python FastAPI Engine
│   ├── api/           # REST/WebSocket endpoints
│   ├── core/          # Core modules (derivation, blockchain clients)
│   ├── heuristics/    # Bitcoin chain analysis (integrated in core/bitcoin.py)
│   ├── config/        # Zero-key endpoint configuration
│   ├── utils/         # Helper utilities
│   └── data/          # Local data storage
├── frontend/          # Next.js Dashboard
├── data/              # Sample/test data files
└── scripts/           # Run scripts and deployment
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Bitcoin Core (optional, for full block file parsing)

### One-Line Setup

```bash
./scripts/setup.sh
```

### Manual Setup

#### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
uvicorn api.main:app --port 8000
```

#### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 for the dashboard, http://localhost:8000/docs for API docs.

## Zero-Key Endpoints

### EVM Networks
| Chain | RPC | Explorer |
|-------|-----|----------|
| Ethereum | cloudflare-eth.com, drpc.org | Etherscan |
| Base | base.drpc.org, mainnet.base.org | BaseScan |
| BSC | bsc-dataseed.binance.org | BscScan |
| Polygon | polygon.drpc.org | PolygonScan |

### Solana
- api.mainnet-beta.solana.com
- public-api.solfma.xyz

### Bitcoin
- Local Bitcoin Core RPC (recommended)
- Peer-to-peer mode (no RPC needed)

## Core Modules

### Module 1: Zero-Key EVM & Solana Forensics

```bash
curl -X POST http://localhost:8000/api/v1/evm/analyze \
  -H "Content-Type: application/json" \
  -d '{"address": "0x...", "chains": ["ethereum", "base"]}'
```

### Module 2: Bitcoin UTXO Parser & Heuristics

```bash
curl -X POST http://localhost:8000/api/v1/bitcoin/analyze \
  -H "Content-Type: application/json" \
  -d '{"block_data_path": "/path/to/blocks", "run_heuristics": true}'
```

## Security

- **Air-gap safe**: All key derivation is local
- **Zero keys**: No commercial API keys required
- **No telemetry**: No external analytics or tracking
- **Private keys stay local**: Only public addresses derived

## Docker Deployment

```bash
docker-compose up -d
```

## License

MIT - Educational and forensic use only.