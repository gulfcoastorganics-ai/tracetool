"""Repeatable, stage-separated Key Lab benchmarks."""

import platform
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List

from .crypto import ENGINES, address_from_hash160, correctness_oracle, hash160, ripemd160, sha256
from .models import BenchmarkRequest, BenchmarkResult, BenchmarkStageResult


STAGES = ("ECC_PUBLIC_KEY", "SHA256", "RIPEMD160", "HASH160", "ADDRESS_ENCODING", "FULL_PIPELINE", "CONTROLLER_OVERHEAD", "MULTICORE_SCALING")


def _measure(stage: str, operation: Callable[[int], object], request: BenchmarkRequest) -> BenchmarkStageResult:
    samples = []
    total_operations = request.range_size
    def run_sample():
        if stage != "MULTICORE_SCALING" or request.worker_count == 1:
            for scalar in range(1, request.range_size + 1):
                operation(scalar)
            return
        chunks = [list(range(start, request.range_size + 1, request.worker_count)) for start in range(1, request.worker_count + 1)]
        with ThreadPoolExecutor(max_workers=request.worker_count, thread_name_prefix="keylab-bench") as pool:
            list(pool.map(lambda chunk: [operation(scalar) for scalar in chunk], chunks))
    for _ in range(request.warmup_count):
        for scalar in range(1, min(request.range_size, 50) + 1): operation(scalar)
    for _ in range(request.sample_count):
        started = time.perf_counter()
        run_sample()
        samples.append(time.perf_counter() - started)
    mean = statistics.mean(samples)
    median = statistics.median(samples)
    stddev = statistics.stdev(samples) if len(samples) > 1 else 0.0
    return BenchmarkStageResult(stage=stage, operations=total_operations * request.sample_count, elapsed_seconds=sum(samples), ops_per_second=(total_operations * request.sample_count) / max(sum(samples), 1e-9), median=median, mean=mean, standard_deviation=stddev, minimum=min(samples), maximum=max(samples), warmup_count=request.warmup_count, sample_count=request.sample_count, worker_count=request.worker_count)


def run_benchmark(request: BenchmarkRequest) -> BenchmarkResult:
    correctness = correctness_oracle()
    engines = ["coincurve", "bitcoinlib"] if request.engine == "compare" else [request.engine]
    results: List[BenchmarkStageResult] = []
    for engine in engines:
        material = ENGINES[engine]
        stages = request.stages
        if "all" in stages:
            stages = list(STAGES)
        for stage in stages:
            if stage not in STAGES:
                continue
            if stage == "ECC_PUBLIC_KEY": operation = lambda scalar, fn=material: bytes.fromhex(fn(scalar).public_key_hex)
            elif stage == "SHA256": operation = lambda scalar, fn=material: sha256(bytes.fromhex(fn(scalar).public_key_hex))
            elif stage == "RIPEMD160": operation = lambda scalar, fn=material: ripemd160(sha256(bytes.fromhex(fn(scalar).public_key_hex)))
            elif stage == "HASH160": operation = lambda scalar, fn=material: hash160(bytes.fromhex(fn(scalar).public_key_hex))
            elif stage == "ADDRESS_ENCODING": operation = lambda scalar, fn=material: address_from_hash160(bytes.fromhex(fn(scalar).hash160_hex), "p2pkh")
            elif stage == "FULL_PIPELINE": operation = material
            elif stage == "MULTICORE_SCALING": operation = material
            else: operation = lambda scalar: scalar
            measured = _measure(stage, operation, request)
            measured.stage = f"{engine}:{stage}"
            results.append(measured)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        commit = "unavailable"
    try:
        bitcoinlib_version = __import__("importlib.metadata", fromlist=["version"]).version("bitcoinlib")
    except Exception:
        bitcoinlib_version = "unavailable"
    try:
        coincurve_version = __import__("importlib.metadata", fromlist=["version"]).version("coincurve")
    except Exception:
        coincurve_version = "unavailable"
    output = BenchmarkResult(timestamp=datetime.now(timezone.utc).isoformat(), engine=request.engine, engines=engines, python_version=platform.python_version(), cpu_architecture=platform.machine(), logical_cpu_count=__import__("os").cpu_count() or 1, worker_count=request.worker_count, sample_count=request.sample_count, range_size=request.range_size, reproducible=True, correctness=correctness, results=results, metadata={"method": "repeated perf_counter samples; correctness oracle precedes measurements", "network": "disabled", "git_commit": commit, "bitcoinlib_version": bitcoinlib_version, "coincurve_version": coincurve_version, "pyperf_methodology": "warmup/calibration-style repeated samples"})
    output_dir = Path("data/keylab/benchmarks")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "latest.json").write_text(output.model_dump_json(indent=2))
    return output
