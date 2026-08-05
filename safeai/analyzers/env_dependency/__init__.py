"""Environment and credential dependency inventory (CE 1.5).

Detects *references* to configuration and credential sources — names and
source locations only, never values. SafeAI records that an agent depends
on ``DATABASE_URL`` or an AWS Secrets Manager entry, not what the value is.
"""

from safeai.analyzers.env_dependency.analyzer import EnvDependencyAnalyzer

__all__ = ["EnvDependencyAnalyzer"]
