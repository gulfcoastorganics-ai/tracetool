"""Profile registry facade kept separate from executable search logic."""

from .profiles import all_profiles, get_profile

__all__ = ["all_profiles", "get_profile"]
