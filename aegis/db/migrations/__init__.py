"""Migration registry.

Only module names are listed here; the runner imports each module and reads
``VERSION`` / ``NAME`` / ``apply``. Adding a migration means adding one module
and appending it to this tuple.
"""

MIGRATION_MODULES = (
    "m0001_initial",
    "m0002_assets",
    "m0003_risks",
    "m0004_controls",
    "m0005_remediation",
)
