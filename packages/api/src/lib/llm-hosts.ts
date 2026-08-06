/**
 * Hostname fragments for known AI/LLM providers.
 *
 * Mirrors the gateway's `is_llm_host`; keep the two lists in sync. A request
 * whose host contains one of these fragments is treated as AI-provider traffic.
 */
export const LLM_HOST_FRAGMENTS = [
  "anthropic.com",
  "openai.com",
  "chatgpt.com",
  "deepseek.com",
  "groq.com",
  "openrouter.ai",
  "moonshot.cn",
  "generativelanguage.googleapis.com",
] as const;
