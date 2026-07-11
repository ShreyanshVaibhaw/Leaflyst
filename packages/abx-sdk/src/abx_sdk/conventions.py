"""The ONLY SDK module allowed to contain raw OTel ``gen_ai.*`` strings.

gen_ai semantic conventions are experimental and churning (blueprint 5.2).
Everything else imports names from here; ingest-side normalization lives in
apps/api .../normalize.py, the only other place raw attribute strings may appear.
Pinned reference: open-telemetry/semantic-conventions v1.41.0, commit e018fe6.
"""

from typing import Final

SCHEMA_URL: Final = "https://opentelemetry.io/schemas/1.41.0"

OPERATION_NAME: Final = "gen_ai.operation.name"
PROVIDER_NAME: Final = "gen_ai.provider.name"
REQUEST_MODEL: Final = "gen_ai.request.model"
RESPONSE_MODEL: Final = "gen_ai.response.model"
AGENT_ID: Final = "gen_ai.agent.id"
AGENT_NAME: Final = "gen_ai.agent.name"
CONVERSATION_ID: Final = "gen_ai.conversation.id"
TOOL_NAME: Final = "gen_ai.tool.name"
TOOL_CALL_ARGUMENTS: Final = "gen_ai.tool.call.arguments"
TOOL_CALL_RESULT: Final = "gen_ai.tool.call.result"
INPUT_MESSAGES: Final = "gen_ai.input.messages"
OUTPUT_MESSAGES: Final = "gen_ai.output.messages"
USAGE_INPUT_TOKENS: Final = "gen_ai.usage.input_tokens"
USAGE_OUTPUT_TOKENS: Final = "gen_ai.usage.output_tokens"

INVOKE_AGENT: Final = "invoke_agent"
CHAT: Final = "chat"
EXECUTE_TOOL: Final = "execute_tool"
