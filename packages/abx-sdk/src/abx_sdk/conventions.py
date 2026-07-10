"""The ONLY module in the SDK allowed to contain raw OTel gen_ai.* attribute strings.

gen_ai semantic conventions are experimental and churning (blueprint 5.2).
Everything else imports names from here; ingest-side normalization lives in
apps/api .../normalize.py, the only other place raw attribute strings may appear.
Pinned reference: open-telemetry/semantic-conventions-genai (pin to commit, repo is untagged).
"""

# Populated in Phase 5.
