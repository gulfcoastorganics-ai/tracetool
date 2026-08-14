"""In-memory Key Lab job controller."""

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from .benchmark import run_benchmark
from .models import KeyLabCapabilities, SyntheticSearchRequest, VanityRequest
from .synthetic import run_synthetic
from .vanity import generate_vanity


class KeyLabService:
    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

    def capabilities(self) -> KeyLabCapabilities:
        return KeyLabCapabilities(engines=["coincurve", "bitcoinlib"], address_types=["p2pkh", "p2wpkh"], stages=["ECC_PUBLIC_KEY", "SHA256", "RIPEMD160", "HASH160", "ADDRESS_ENCODING", "FULL_PIPELINE", "CONTROLLER_OVERHEAD", "MULTICORE_SCALING"], max_synthetic_range=100_000, max_vanity_runtime_seconds=300, notes=["All Key Lab work is local-only.", "Generated private keys are held only in the response/job memory and are never written to disk.", "Split-key is disabled until independently reviewed protocol support is available."])

    def create_vanity_job(self, request: VanityRequest) -> Dict[str, Any]:
        job_id = str(uuid.uuid4())
        cancel = threading.Event()
        with self.lock:
            self.jobs[job_id] = {"id": job_id, "state": "queued", "created_at": datetime.now(timezone.utc).isoformat(), "request": request.model_dump(), "cancel": cancel}
        thread = threading.Thread(target=self._run_vanity, args=(job_id, request, cancel), daemon=True)
        thread.start()
        return self.public_job(job_id)

    def _run_vanity(self, job_id, request, cancel):
        self.jobs[job_id]["state"] = "running"
        try:
            result = generate_vanity(request, cancel)
            self.jobs[job_id].update({"state": result.status, "result": result.model_dump()})
        except Exception as exc:
            self.jobs[job_id].update({"state": "failed", "error": str(exc)})

    def get_job(self, job_id: str):
        if job_id not in self.jobs:
            return None
        return self.public_job(job_id)

    def cancel_job(self, job_id: str):
        job = self.jobs.get(job_id)
        if not job:
            return None
        job["cancel"].set()
        if job["state"] in ("queued", "running"):
            job["state"] = "cancelled"
        return self.public_job(job_id)

    def public_job(self, job_id):
        job = self.jobs[job_id]
        return {key: value for key, value in job.items() if key not in ("cancel", "request")}

    def benchmark(self, request):
        return run_benchmark(request)

    def synthetic(self, request):
        return run_synthetic(request)


keylab_service = KeyLabService()
