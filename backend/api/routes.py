"""
API Routes for Chain-Trace Backend
Run via: uvicorn backend.api.main:app --reload
"""

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import json

from backend.core.derivation import DerivationEngine, MultiChainExplorer, SolanaExplorer
from backend.core.bitcoin import UTXOParser, BitcoinForensicsReport, BitcoinHeuristics, TxOutput, BitcoinTransaction
from backend.config.settings import get_all_chains, get_chain_config, SOLANA_CONFIG
from backend.keylab.models import BenchmarkRequest, KeyLabCapabilities, SplitKeyRequest, SyntheticSearchRequest, VanityRequest
from backend.keylab.service import keylab_service
from backend.keylab.split_key import split_key
from backend.entropy.models import EntropyAnalysisRequest, PartialMnemonicRequest, SourceAuditRequest, SyntheticWeakGeneratorConfig
from backend.entropy.registry import all_profiles, get_profile
from backend.entropy.service import entropy_service
from backend.entropy_assurance.models import CompareRequest, GeneratorAuditRequest, RuntimeProbeRequest, SelfAuditRequest, SourceAuditRequest
from backend.entropy_assurance.service import assurance_service
from backend.wallet_recovery.models import AddressVerificationRequest, ArtifactInspectRequest, ArtifactPasswordRequest, BackupFormatRequest, BSMSInspectRequest, DerivationExploreRequest, ExtendedKeyGapRequest, GeneratorAnalysisRequest, MnemonicAnalysisRequest, PolicyInspectRequest, RecoveryAnalysisRequest, RecoveryPlanRequest, RecoverySessionRequest, Slip39RecoveryRequest
from backend.wallet_recovery.service import wallet_recovery_service

app = FastAPI(
    title="Chain-Trace Forensics API",
    description="Zero-key cryptocurrency forensics engine",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

derivation_engine = DerivationEngine()
evm_explorer = MultiChainExplorer(derivation_engine)
solana_explorer = SolanaExplorer()


# Request/Response Models
class DerivationRequest(BaseModel):
    mnemonic: str
    derivation_type: str = "ethereum"
    count: int = 10
    passphrase: str = ""


class AnalysisRequest(BaseModel):
    address: str
    chains: Optional[List[str]] = None


class BitcoinAnalyzeRequest(BaseModel):
    block_data_path: Optional[str] = None
    max_transactions: int = 1000
    run_heuristics: bool = True


class WebSocketMessage(BaseModel):
    type: str
    data: Dict[str, Any]


@app.get("/")
async def root():
    return {
        "name": "Chain-Trace Forensics API",
        "version": "0.1.0",
        "description": "Zero-key cryptocurrency forensics engine",
        "endpoints": {
            "derivation": "/api/v1/derive",
            "analyze_evm": "/api/v1/evm/analyze",
            "analyze_solana": "/api/v1/solana/analyze",
            "analyze_bitcoin": "/api/v1/bitcoin/analyze",
            "chains": "/api/v1/chains"
        }
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/v1/keylab/capabilities", response_model=KeyLabCapabilities)
async def keylab_capabilities():
    return keylab_service.capabilities()


@app.get("/api/v1/entropy/capabilities")
async def entropy_capabilities():
    return {
        "enabled": True,
        "analysis_only_by_default": True,
        "synthetic_recovery": True,
        "external_target_recovery": False,
        "profile_count": len(all_profiles()),
        "feasibility_thresholds": {"trivial_lab": "<=2^16", "small_bounded": "<=2^24", "practical_with_constraints": "<=2^32", "expensive": "<=2^48", "infeasible": ">2^48"},
        "notes": ["Mnemonic validity does not establish entropy provenance.", "Synthetic recovery requires a Chain-Trace-issued session token.", "Statistical randomness tests are not proof of cryptographic security."],
    }


@app.get("/api/v1/entropy/profiles")
async def entropy_profiles():
    return {"profiles": [profile.model_dump(mode="json") for profile in all_profiles()]}


@app.get("/api/v1/entropy/profiles/{profile_id}")
async def entropy_profile(profile_id: str):
    profile = get_profile(profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Entropy vulnerability profile not found")
    return profile


@app.post("/api/v1/entropy/analyze")
async def entropy_analyze(request: EntropyAnalysisRequest):
    try:
        return entropy_service.analyze(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/entropy/estimate")
async def entropy_estimate(request: PartialMnemonicRequest):
    try:
        return entropy_service.partial_estimate(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/entropy/patch/validate")
async def entropy_patch_validate(request: SourceAuditRequest):
    try:
        return entropy_service.validate_patch(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/entropy/lab/generate")
async def entropy_lab_generate(request: SyntheticWeakGeneratorConfig):
    try:
        return entropy_service.generate(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class EntropyRecoveryRequest(BaseModel):
    session_token: str = Field(min_length=10, max_length=100)


class EntropyPatchCompareRequest(BaseModel):
    model: str = Field(pattern=r"^(16|20|24|32|timestamp|repeated|truncated)$")


@app.post("/api/v1/entropy/lab/recover")
async def entropy_lab_recover(request: EntropyRecoveryRequest):
    try:
        return entropy_service.recover(request.session_token)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@app.post("/api/v1/entropy/lab/compare-patch")
async def entropy_lab_compare_patch(request: EntropyPatchCompareRequest):
    try:
        return entropy_service.compare_patch(request.model)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v1/entropy-assurance/capabilities")
async def entropy_assurance_capabilities():
    return {
        "enabled": True,
        "nominal_target_bits": 256,
        "exact_random_bytes_required": 32,
        "assurance_levels": ["VERIFIED_CONSTRUCTION", "STRONG_EVIDENCE", "PARTIAL_EVIDENCE", "INSUFFICIENT_EVIDENCE", "FAILED"],
        "environments": ["python-native", "node", "browser", "web-worker", "wasm", "container"],
        "statistical_tests": "SUPPLEMENTARY_DIAGNOSTICS",
        "secrets_returned": False,
        "notes": ["Output width is not proof of entropy.", "Effective entropy is bounded by the smallest trusted source state and preserved input width.", "Browser/WASM and native paths require separate audits."],
    }


@app.post("/api/v1/entropy-assurance/audit-source")
async def entropy_assurance_audit_source(request: SourceAuditRequest):
    try:
        return assurance_service.audit_source(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/entropy-assurance/audit-generator")
async def entropy_assurance_audit_generator(request: GeneratorAuditRequest):
    try:
        return assurance_service.audit_generator(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/entropy-assurance/runtime-probe")
async def entropy_assurance_runtime_probe(request: RuntimeProbeRequest):
    try:
        return assurance_service.runtime_probe(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/entropy-assurance/self-audit")
async def entropy_assurance_self_audit(request: SelfAuditRequest = SelfAuditRequest()):
    try:
        return assurance_service.self_audit(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/v1/entropy-assurance/compare")
async def entropy_assurance_compare(request: CompareRequest):
    try:
        return assurance_service.compare(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v1/wallet-recovery/capabilities")
async def wallet_recovery_capabilities():
    return wallet_recovery_service.capabilities()


@app.post("/api/v1/wallet-recovery/analyze")
async def wallet_recovery_analyze(request: RecoveryAnalysisRequest):
    try:
        return wallet_recovery_service.analyze(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Recovery assessment could not be completed")


@app.post("/api/v1/wallet-recovery/identify-early-wallet")
async def wallet_recovery_identify_early_wallet(request: RecoveryAnalysisRequest):
    try:
        return wallet_recovery_service.identify_early_wallet(request.evidence)
    except Exception:
        raise HTTPException(status_code=400, detail="Early-wallet identification could not be completed")


@app.post("/api/v1/wallet-recovery/derive")
async def wallet_recovery_derive(request: DerivationExploreRequest):
    try:
        return wallet_recovery_service.derive(request)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=400, detail="Derivation exploration failed")


@app.post("/api/v1/wallet-recovery/verify-address")
async def wallet_recovery_verify_address(request: AddressVerificationRequest):
    try:
        return wallet_recovery_service.verify_address(request)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=400, detail="Address verification failed")


@app.post("/api/v1/wallet-recovery/analyze-mnemonic")
async def wallet_recovery_analyze_mnemonic(request: MnemonicAnalysisRequest):
    try:
        return wallet_recovery_service.analyze_mnemonic(request)
    except Exception:
        raise HTTPException(status_code=400, detail="Mnemonic feasibility analysis failed")


@app.post("/api/v1/wallet-recovery/analyze-generator")
async def wallet_recovery_analyze_generator(request: GeneratorAnalysisRequest):
    try:
        return wallet_recovery_service.analyze_generator(request)
    except Exception:
        raise HTTPException(status_code=400, detail="Generator provenance analysis failed")


@app.post("/api/v1/wallet-recovery/build-plan")
async def wallet_recovery_build_plan(request: RecoveryPlanRequest):
    try:
        return wallet_recovery_service.build_plan(request)
    except Exception:
        raise HTTPException(status_code=400, detail="Recovery plan could not be built")


@app.post("/api/v1/wallet-recovery/session")
async def wallet_recovery_session(request: RecoverySessionRequest):
    try:
        return wallet_recovery_service.create_session(request)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=400, detail="Recovery session could not be created")


@app.post("/api/v1/wallet-recovery/artifact/inspect")
async def wallet_recovery_artifact_inspect(request: ArtifactInspectRequest):
    try:
        return wallet_recovery_service.inspect_artifact(request.artifact)
    except Exception:
        raise HTTPException(status_code=400, detail="Artifact inspection failed")


@app.post("/api/v1/wallet-recovery/artifact/verify-password")
async def wallet_recovery_artifact_verify_password(request: ArtifactPasswordRequest):
    try:
        return wallet_recovery_service.verify_artifact_password(request.artifact, request.password)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception:
        raise HTTPException(status_code=400, detail="Artifact password verification failed")


@app.post("/api/v1/wallet-recovery/extended-key/gap-discover")
async def wallet_recovery_extended_key_gap(request: ExtendedKeyGapRequest):
    try:
        return wallet_recovery_service.discover_gap(request)
    except Exception:
        raise HTTPException(status_code=400, detail="Extended-key gap discovery failed")


@app.post("/api/v1/wallet-recovery/format/classify")
async def wallet_recovery_format_classify(request: BackupFormatRequest):
    try:
        return wallet_recovery_service.classify_backup(request.backup)
    except Exception:
        raise HTTPException(status_code=400, detail="Backup format classification failed")


@app.post("/api/v1/wallet-recovery/slip39/reconstruct")
async def wallet_recovery_slip39_reconstruct(request: Slip39RecoveryRequest):
    try:
        return wallet_recovery_service.reconstruct_slip39(request.shares, request.passphrase)
    except Exception:
        raise HTTPException(status_code=400, detail="SLIP-0039 reconstruction failed")


@app.post("/api/v1/wallet-recovery/policy/bip388/inspect")
async def wallet_recovery_bip388_inspect(request: PolicyInspectRequest):
    from backend.wallet_recovery.policy_artifacts import inspect_bip388
    return inspect_bip388(request.policy)


@app.post("/api/v1/wallet-recovery/policy/bsms/inspect")
async def wallet_recovery_bsms_inspect(request: BSMSInspectRequest):
    from backend.wallet_recovery.policy_artifacts import inspect_bsms
    return inspect_bsms(request.artifact)


@app.post("/api/v1/keylab/benchmark")
async def keylab_benchmark(request: BenchmarkRequest):
    try:
        return keylab_service.benchmark(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/keylab/vanity")
async def keylab_vanity(request: VanityRequest):
    try:
        from backend.keylab.vanity import generate_vanity
        return generate_vanity(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/keylab/synthetic")
async def keylab_synthetic(request: SyntheticSearchRequest):
    try:
        return keylab_service.synthetic(request)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/keylab/split-key")
async def keylab_split_key(request: SplitKeyRequest):
    return split_key(request)


@app.post("/api/v1/keylab/vanity/jobs")
async def keylab_create_vanity_job(request: VanityRequest):
    return keylab_service.create_vanity_job(request)


@app.get("/api/v1/keylab/jobs/{job_id}")
async def keylab_get_job(job_id: str):
    result = keylab_service.get_job(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Key Lab job not found")
    return result


@app.delete("/api/v1/keylab/jobs/{job_id}")
async def keylab_cancel_job(job_id: str):
    result = keylab_service.cancel_job(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Key Lab job not found")
    return result


@app.get("/api/v1/chains")
async def get_chains():
    return {
        "evm": get_all_chains(),
        "solana": "solana",
        "bitcoin": "bitcoin"
    }


@app.post("/api/v1/derive")
async def derive_addresses(request: DerivationRequest):
    try:
        addresses = derivation_engine.derive_addresses(
            mnemonic=request.mnemonic,
            derivation_type=request.derivation_type,
            count=request.count,
            passphrase=request.passphrase
        )
        
        return {
            "success": True,
            "addresses": [{
                "path": a.path,
                "address": a.address,
                "label": a.label,
                "chain_type": a.chain_type
            } for a in addresses],
            "derivation_type": request.derivation_type,
            "count": len(addresses)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/evm/analyze")
async def analyze_evm_address(request: AnalysisRequest):
    chains = request.chains or get_all_chains()
    
    try:
        result = evm_explorer.analyze_address(
            address=request.address,
            chains=chains
        )
        
        return {
            "address": request.address,
            "timestamp": result.get('timestamp', datetime.utcnow().isoformat()),
            "chains": result['chains']
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/solana/analyze")
async def analyze_solana_address(request: AnalysisRequest):
    try:
        result = solana_explorer.analyze_address(request.address)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/bitcoin/analyze")
async def analyze_bitcoin(request: BitcoinAnalyzeRequest):
    try:
        parser = UTXOParser(request.block_data_path)
        
        transactions = {}
        if request.block_data_path:
            transactions = parser.load_transactions_from_dat(request.block_data_path)
        
        if request.run_heuristics:
            forensics = BitcoinForensicsReport()
            result = forensics.generate(list(transactions.values()))
            return {
                "analysis_timestamp": result['analysis_timestamp'],
                "transactions_analyzed": len(transactions),
                "cioh_clusters": len(result['common_input_ownership']),
                "coinjoins_detected": len(result['coinjoins_detected']),
                "change_addresses": len(result['change_addresses']),
                "peeling_chains": len(result['peeling_chains']),
                "raw_data": result
            }
        
        return {
            "transactions": [json.loads(tx.to_json()) for tx in transactions.values()]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/heuristics/coinjoin")
async def detect_coinjoins_endpoint(
    transactions: List[Dict],
    min_outputs: int = 3
):
    heur = BitcoinHeuristics()
    txs = []
    for tx in transactions:
        outputs = [TxOutput(**o) for o in tx.get('outputs', [])]
        txs.append(BitcoinTransaction(
            txid=tx['txid'],
            inputs=tx.get('inputs', []),
            outputs=outputs,
            timestamp=tx.get('timestamp', 0),
            version=tx.get('version', 1),
            locktime=tx.get('locktime', 0)
        ))
    
    coinjoins = heur.detect_coinjoins(txs, min_outputs)
    
    return {"coinjoins": coinjoins}


@app.post("/api/v1/heuristics/cioh")
async def apply_cioh_endpoint(transactions: List[Dict]):
    heur = BitcoinHeuristics()
    txs = []
    for tx in transactions:
        outputs = [TxOutput(**o) for o in tx.get('outputs', [])]
        txs.append(BitcoinTransaction(
            txid=tx['txid'],
            inputs=tx.get('inputs', []),
            outputs=outputs,
            timestamp=tx.get('timestamp', 0),
            version=tx.get('version', 1),
            locktime=tx.get('locktime', 0)
        ))
    
    clusters = heur.apply_cioh(txs)
    
    return {
        "cioh_clusters": {str(k): list(v) for k, v in clusters.items()},
        "cluster_count": len(clusters)
    }


@app.post("/api/v1/heuristics/change")
async def detect_change_endpoint(transactions: List[Dict]):
    heur = BitcoinHeuristics()
    txs = []
    for tx in transactions:
        outputs = [TxOutput(**o) for o in tx.get('outputs', [])]
        txs.append(BitcoinTransaction(
            txid=tx['txid'],
            inputs=tx.get('inputs', []),
            outputs=outputs,
            timestamp=tx.get('timestamp', 0),
            version=tx.get('version', 1),
            locktime=tx.get('locktime', 0)
        ))
    
    change_addrs = heur.detect_change_addresses(txs)
    
    return {
        "change_addresses": list(change_addrs),
        "count": len(change_addrs)
    }


@app.websocket("/api/v1/ws/blockchain")
async def blockchain_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({
                "status": "connected",
                "timestamp": datetime.utcnow().isoformat()
            })
    except Exception:
        await websocket.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
