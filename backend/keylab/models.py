"""Typed request and result models for the local-only Key Lab."""

from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


AddressType = Literal["p2pkh", "p2wpkh"]
EngineName = Literal["bitcoinlib", "coincurve", "compare"]


class VanityRequest(BaseModel):
    address_type: AddressType = "p2pkh"
    pattern: str = Field(min_length=1, max_length=32)
    case_sensitive: bool = False
    worker_count: int = Field(default=1, ge=1, le=32)
    max_runtime_seconds: float = Field(default=30.0, gt=0, le=300)
    wildcard: bool = False

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("pattern cannot be empty")
        if any(char.isspace() for char in value):
            raise ValueError("pattern cannot contain whitespace")
        return value


class VanityResult(BaseModel):
    status: Literal["found", "completed", "cancelled", "failed"]
    address: Optional[str] = None
    public_key: Optional[str] = None
    private_key: Optional[str] = None
    address_type: AddressType
    pattern: str
    candidates_tested: int
    current_rate: float
    average_rate: float
    elapsed_seconds: float
    estimated_difficulty: float
    estimated_time_remaining: Optional[float] = None
    worker_count: int
    error: Optional[str] = None
    private_key_redacted: bool = False


class BenchmarkRequest(BaseModel):
    engine: EngineName = "coincurve"
    stages: List[str] = Field(default_factory=lambda: ["all"])
    range_size: int = Field(default=2000, ge=10, le=100_000)
    warmup_count: int = Field(default=2, ge=0, le=20)
    sample_count: int = Field(default=5, ge=1, le=30)
    worker_count: int = Field(default=1, ge=1, le=32)


class BenchmarkStageResult(BaseModel):
    stage: str
    operations: int
    elapsed_seconds: float
    ops_per_second: float
    median: float
    mean: float
    standard_deviation: float
    minimum: float
    maximum: float
    warmup_count: int
    sample_count: int
    worker_count: int


class BenchmarkResult(BaseModel):
    timestamp: str
    engine: str
    engines: List[str]
    python_version: str
    cpu_architecture: str
    logical_cpu_count: int
    worker_count: int
    sample_count: int
    range_size: int
    reproducible: bool
    stability_warning: Optional[str] = None
    correctness: Dict[str, Dict[str, str]]
    results: List[BenchmarkStageResult]
    metadata: Dict[str, str] = Field(default_factory=dict)


class SyntheticSearchRequest(BaseModel):
    range_size: int = Field(default=100, ge=2, le=100_000)
    target_position: Optional[int] = Field(default=None, ge=0)
    worker_count: int = Field(default=1, ge=1, le=32)
    engine: Literal["coincurve"] = "coincurve"


class SyntheticSearchResult(BaseModel):
    status: Literal["recovered", "cancelled", "failed"]
    start: int
    end: int
    target_address: str
    range_size: int
    candidates_checked: int
    elapsed_seconds: float
    candidates_per_second: float
    target_position: Optional[int] = None
    verification: bool
    secret_redacted: bool = True
    error: Optional[str] = None


class SplitKeyRequest(BaseModel):
    address_type: AddressType = "p2pkh"
    pattern: str = Field(min_length=1, max_length=32)


class SplitKeyResult(BaseModel):
    enabled: bool
    status: Literal["disabled", "found", "failed"]
    message: str
    address: Optional[str] = None
    public_key: Optional[str] = None


class KeyLabCapabilities(BaseModel):
    enabled: bool = True
    network_calls: bool = False
    engines: List[str]
    address_types: List[str]
    stages: List[str]
    split_key_enabled: bool = False
    synthetic_search_enabled: bool = True
    max_synthetic_range: int
    max_vanity_runtime_seconds: int
    notes: List[str]
