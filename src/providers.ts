import { z } from 'zod';
import type { ModelSpec } from './types.js';

export type OutputFormat = 'auto' | 'json_schema' | 'json_object' | 'prompt';
export type ProviderProtocol =
  'openai-responses' | 'openai-chat' | 'anthropic' | 'gemini' | 'cohere' | 'perplexity';
export interface ProviderDefinition {
  id: string;
  name: string;
  protocol: ProviderProtocol;
  endpoint?: string;
  apiKeyEnv: string;
  defaultFormat: Exclude<OutputFormat, 'auto'>;
  documentationUrl: string;
  local?: boolean;
  tokenParameter?: 'max_tokens' | 'max_completion_tokens';
  formats?: readonly Exclude<OutputFormat, 'auto'>[];
}

const catalog = [
  {
    id: 'openai',
    name: 'OpenAI',
    protocol: 'openai-responses',
    endpoint: 'https://api.openai.com/v1/responses',
    apiKeyEnv: 'OPENAI_API_KEY',
    defaultFormat: 'json_schema',
    documentationUrl: 'https://developers.openai.com/api/reference/resources/responses/methods/create',
  },
  {
    id: 'azure-openai',
    name: 'Azure OpenAI',
    protocol: 'openai-responses',
    apiKeyEnv: 'AZURE_OPENAI_API_KEY',
    defaultFormat: 'json_schema',
    documentationUrl: 'https://learn.microsoft.com/en-us/rest/api/aifoundry/azureopenai/responses',
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    protocol: 'anthropic',
    endpoint: 'https://api.anthropic.com/v1/messages',
    apiKeyEnv: 'ANTHROPIC_API_KEY',
    defaultFormat: 'json_schema',
    formats: ['json_schema', 'prompt'],
    documentationUrl: 'https://platform.claude.com/docs/en/build-with-claude/structured-outputs',
  },
  {
    id: 'gemini',
    name: 'Google Gemini',
    protocol: 'gemini',
    endpoint: 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent',
    apiKeyEnv: 'GEMINI_API_KEY',
    defaultFormat: 'json_schema',
    documentationUrl: 'https://ai.google.dev/api/generate-content',
  },
  {
    id: 'cohere',
    name: 'Cohere',
    protocol: 'cohere',
    endpoint: 'https://api.cohere.com/v2/chat',
    apiKeyEnv: 'COHERE_API_KEY',
    defaultFormat: 'json_schema',
    documentationUrl: 'https://docs.cohere.com/v2/reference/chat',
  },
  {
    id: 'groq',
    name: 'Groq',
    protocol: 'openai-chat',
    endpoint: 'https://api.groq.com/openai/v1/chat/completions',
    apiKeyEnv: 'GROQ_API_KEY',
    defaultFormat: 'json_object',
    tokenParameter: 'max_completion_tokens',
    documentationUrl: 'https://console.groq.com/docs/api-reference',
  },
  {
    id: 'deepseek',
    name: 'DeepSeek',
    protocol: 'openai-chat',
    endpoint: 'https://api.deepseek.com/chat/completions',
    apiKeyEnv: 'DEEPSEEK_API_KEY',
    defaultFormat: 'json_object',
    formats: ['json_object', 'prompt'],
    documentationUrl: 'https://api-docs.deepseek.com/api/create-chat-completion/',
  },
  {
    id: 'xai',
    name: 'xAI',
    protocol: 'openai-responses',
    endpoint: 'https://api.x.ai/v1/responses',
    apiKeyEnv: 'XAI_API_KEY',
    defaultFormat: 'json_schema',
    documentationUrl: 'https://docs.x.ai/developers/model-capabilities/text/structured-outputs',
  },
  {
    id: 'mistral',
    name: 'Mistral',
    protocol: 'openai-chat',
    endpoint: 'https://api.mistral.ai/v1/chat/completions',
    apiKeyEnv: 'MISTRAL_API_KEY',
    defaultFormat: 'json_schema',
    documentationUrl: 'https://docs.mistral.ai/api',
  },
  {
    id: 'together',
    name: 'Together AI',
    protocol: 'openai-chat',
    endpoint: 'https://api.together.ai/v1/chat/completions',
    apiKeyEnv: 'TOGETHER_API_KEY',
    defaultFormat: 'json_object',
    documentationUrl: 'https://docs.together.ai/reference/chat-completions',
  },
  {
    id: 'fireworks',
    name: 'Fireworks AI',
    protocol: 'openai-chat',
    endpoint: 'https://api.fireworks.ai/inference/v1/chat/completions',
    apiKeyEnv: 'FIREWORKS_API_KEY',
    defaultFormat: 'json_object',
    documentationUrl: 'https://docs.fireworks.ai/api-reference/post-chatcompletions',
  },
  {
    id: 'openrouter',
    name: 'OpenRouter',
    protocol: 'openai-chat',
    endpoint: 'https://openrouter.ai/api/v1/chat/completions',
    apiKeyEnv: 'OPENROUTER_API_KEY',
    defaultFormat: 'json_object',
    documentationUrl: 'https://openrouter.ai/docs/guides/features/structured-outputs',
  },
  {
    id: 'cerebras',
    name: 'Cerebras',
    protocol: 'openai-chat',
    endpoint: 'https://api.cerebras.ai/v1/chat/completions',
    apiKeyEnv: 'CEREBRAS_API_KEY',
    defaultFormat: 'json_object',
    tokenParameter: 'max_completion_tokens',
    documentationUrl: 'https://inference-docs.cerebras.ai/api-reference/chat-completions',
  },
  {
    id: 'nvidia',
    name: 'NVIDIA NIM',
    protocol: 'openai-chat',
    endpoint: 'https://integrate.api.nvidia.com/v1/chat/completions',
    apiKeyEnv: 'NVIDIA_API_KEY',
    defaultFormat: 'prompt',
    documentationUrl: 'https://docs.api.nvidia.com/nim/reference/openai-gpt-oss-120b-infer',
  },
  {
    id: 'sambanova',
    name: 'SambaNova',
    protocol: 'openai-chat',
    endpoint: 'https://api.sambanova.ai/v1/chat/completions',
    apiKeyEnv: 'SAMBANOVA_API_KEY',
    defaultFormat: 'json_object',
    documentationUrl:
      'https://raw.githubusercontent.com/sambanova/sambanova-inference-api-spec/refs/heads/main/openapi.documented.json',
  },
  {
    id: 'huggingface',
    name: 'Hugging Face Inference Providers',
    protocol: 'openai-chat',
    endpoint: 'https://router.huggingface.co/v1/chat/completions',
    apiKeyEnv: 'HF_TOKEN',
    defaultFormat: 'prompt',
    documentationUrl: 'https://huggingface.co/docs/inference-providers/en/tasks/chat-completion',
  },
  {
    id: 'perplexity',
    name: 'Perplexity Agent API',
    protocol: 'perplexity',
    endpoint: 'https://api.perplexity.ai/v1/agent',
    apiKeyEnv: 'PERPLEXITY_API_KEY',
    defaultFormat: 'json_schema',
    formats: ['json_schema', 'prompt'],
    documentationUrl: 'https://docs.perplexity.ai/api-reference/agent-post',
  },
  {
    id: 'openai-compatible',
    name: 'OpenAI-compatible endpoint',
    protocol: 'openai-chat',
    apiKeyEnv: 'OPENAI_API_KEY',
    defaultFormat: 'json_schema',
    documentationUrl:
      'https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create',
  },
  {
    id: 'ollama',
    name: 'Ollama local server',
    protocol: 'openai-chat',
    apiKeyEnv: 'OLLAMA_API_KEY',
    defaultFormat: 'json_schema',
    local: true,
    documentationUrl: 'https://docs.ollama.com/api/openai-compatibility',
  },
  {
    id: 'lmstudio',
    name: 'LM Studio local server',
    protocol: 'openai-chat',
    apiKeyEnv: 'LM_STUDIO_API_KEY',
    defaultFormat: 'json_schema',
    local: true,
    documentationUrl: 'https://lmstudio.ai/docs/developer/openai-compat/structured-output',
  },
  {
    id: 'vllm',
    name: 'vLLM server',
    protocol: 'openai-chat',
    apiKeyEnv: 'VLLM_API_KEY',
    defaultFormat: 'json_schema',
    local: true,
    documentationUrl: 'https://docs.vllm.ai/en/latest/features/structured_outputs/',
  },
  {
    id: 'litellm',
    name: 'LiteLLM gateway',
    protocol: 'openai-chat',
    apiKeyEnv: 'LITELLM_API_KEY',
    defaultFormat: 'json_object',
    local: true,
    documentationUrl: 'https://docs.litellm.ai/docs/completion/json_mode',
  },
] as const satisfies readonly ProviderDefinition[];

export type ModelProvider = (typeof catalog)[number]['id'];
export const PROVIDERS: readonly Readonly<ProviderDefinition>[] = Object.freeze(
  catalog.map((entry) =>
    Object.freeze({
      ...entry,
      ...('formats' in entry ? { formats: Object.freeze([...entry.formats]) } : {}),
    }),
  ),
);
export const PROVIDER_IDS = Object.freeze(catalog.map((entry) => entry.id));
export function providerDefinition(id: string): Readonly<ProviderDefinition> {
  const definition = PROVIDERS.find((entry) => entry.id === id);
  if (!definition) throw new Error('MODEL_PROVIDER_UNKNOWN');
  return definition;
}
export function allowsMissingKey(spec: ModelSpec): boolean {
  return Boolean(
    spec.allow_private_endpoint &&
    (spec.provider === 'openai-compatible' || providerDefinition(spec.provider).local),
  );
}
export function modelOutputFormat(spec: ModelSpec): Exclude<OutputFormat, 'auto'> {
  const definition = providerDefinition(spec.provider);
  const format =
    !spec.output_format || spec.output_format === 'auto' ? definition.defaultFormat : spec.output_format;
  if (definition.formats && !definition.formats.includes(format))
    throw new Error('MODEL_OUTPUT_FORMAT_UNSUPPORTED');
  return format;
}
export function modelEndpoint(spec: ModelSpec): string {
  if (spec.endpoint) return spec.endpoint;
  const definition = providerDefinition(spec.provider);
  if (!definition.endpoint) throw new Error('MODEL_ENDPOINT_MISSING');
  if (definition.protocol !== 'gemini') return definition.endpoint;
  const model = spec.model.replace(/^models\//, '');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(model)) throw new Error('MODEL_ID_INVALID');
  return definition.endpoint.replace('{model}', encodeURIComponent(model));
}

export function buildModelRequest(
  spec: ModelSpec,
  token: string | undefined,
  instruction: string,
  input: string,
  schema: unknown,
  maxOutput: number,
): { url: string; headers: Record<string, string>; body: Record<string, unknown> } {
  const definition = providerDefinition(spec.provider);
  if (!token && !allowsMissingKey(spec)) throw new Error('MODEL_CREDENTIAL_MISSING');
  const url = modelEndpoint(spec);
  const format = modelOutputFormat(spec);
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  const guidance = instruction + `\nReturn only JSON matching this JSON schema: ${JSON.stringify(schema)}`;
  if (definition.protocol === 'anthropic') {
    headers['x-api-key'] = token!;
    headers['anthropic-version'] = '2023-06-01';
    return {
      url,
      headers,
      body: {
        model: spec.model,
        max_tokens: maxOutput,
        system: guidance,
        messages: [{ role: 'user', content: input }],
        ...(format === 'json_schema' ? { output_config: { format: { type: 'json_schema', schema } } } : {}),
      },
    };
  }
  if (definition.protocol === 'gemini') {
    headers['x-goog-api-key'] = token!;
    return {
      url,
      headers,
      body: {
        systemInstruction: { parts: [{ text: guidance }] },
        contents: [{ role: 'user', parts: [{ text: input }] }],
        generationConfig: {
          maxOutputTokens: maxOutput,
          candidateCount: 1,
          ...(format === 'prompt'
            ? {}
            : {
                responseFormat: {
                  text: { mimeType: 'APPLICATION_JSON', ...(format === 'json_schema' ? { schema } : {}) },
                },
              }),
        },
      },
    };
  }
  if (token) {
    if (spec.provider === 'azure-openai') headers['api-key'] = token;
    else headers.authorization = `Bearer ${token}`;
  }
  if (definition.protocol === 'openai-responses' || definition.protocol === 'perplexity') {
    const body: Record<string, unknown> = {
      model: spec.model,
      instructions: guidance,
      input,
      store: false,
      background: false,
      max_output_tokens: maxOutput,
    };
    if (definition.protocol === 'perplexity') {
      Object.assign(body, { tools: [], tool_choice: 'none', max_steps: 1, stream: false });
      if (format === 'json_schema')
        body.response_format = { type: 'json_schema', json_schema: { name: 'securityassessment', schema } };
    } else if (format !== 'prompt') {
      body.text = {
        format:
          format === 'json_schema'
            ? { type: 'json_schema', name: 'security_assessment', strict: true, schema }
            : { type: 'json_object' },
      };
    }
    return { url, headers, body };
  }
  const body: Record<string, unknown> = {
    model: spec.model,
    [definition.tokenParameter ?? 'max_tokens']: maxOutput,
    stream: false,
    messages: [
      { role: 'system', content: guidance },
      { role: 'user', content: input },
    ],
  };
  if (format !== 'prompt') {
    body.response_format =
      definition.protocol === 'cohere'
        ? { type: 'json_object', ...(format === 'json_schema' ? { schema } : {}) }
        : format === 'json_schema'
          ? { type: 'json_schema', json_schema: { name: 'security_assessment', strict: true, schema } }
          : { type: 'json_object' };
  }
  if (spec.provider === 'openrouter' && format !== 'prompt') body.provider = { require_parameters: true };
  return { url, headers, body };
}

const recordSchema = z.record(z.string(), z.unknown());
const textBlocks = z.array(z.object({ type: z.string(), text: z.string().optional() }));
function responseText(text: string): string {
  if (!text.trim()) throw new Error('MODEL_EMPTY_OUTPUT');
  return text;
}
export function parseModelResponse(spec: ModelSpec, value: unknown): string {
  const protocol = providerDefinition(spec.provider).protocol;
  const record = recordSchema.parse(value);
  if (record.error) throw new Error('MODEL_PROVIDER_ERROR');
  if (protocol === 'openai-responses' || protocol === 'perplexity') {
    if (record.status !== 'completed') throw new Error('MODEL_INCOMPLETE');
    const output = z
      .array(z.object({ type: z.string(), status: z.string().optional(), content: textBlocks.optional() }))
      .parse(record.output);
    if (output.some((item) => item.content?.some((part) => part.type === 'refusal')))
      throw new Error('MODEL_REFUSAL');
    if (output.some((item) => !['message', 'reasoning'].includes(item.type)))
      throw new Error('MODEL_UNEXPECTED_TOOL');
    if (output.some((item) => item.status && item.status !== 'completed'))
      throw new Error('MODEL_INCOMPLETE');
    return responseText(
      output
        .filter((item) => item.type === 'message')
        .flatMap((item) => item.content ?? [])
        .filter((part) => part.type === 'output_text')
        .map((part) => part.text ?? '')
        .join(''),
    );
  }
  if (protocol === 'gemini') {
    const feedback =
      record.promptFeedback === undefined ? undefined : recordSchema.parse(record.promptFeedback);
    if (feedback?.blockReason) throw new Error('MODEL_REFUSAL');
    const candidates = z
      .array(
        z.object({
          finishReason: z.string(),
          content: z.object({
            parts: z.array(
              z.object({
                text: z.string().optional(),
                thought: z.boolean().optional(),
                functionCall: z.unknown().optional(),
                functionResponse: z.unknown().optional(),
                executableCode: z.unknown().optional(),
                codeExecutionResult: z.unknown().optional(),
                toolCall: z.unknown().optional(),
                toolResponse: z.unknown().optional(),
              }),
            ),
          }),
          safetyRatings: z.array(z.object({ blocked: z.boolean().optional() })).optional(),
        }),
      )
      .length(1)
      .parse(record.candidates);
    const candidate = candidates[0]!;
    if (
      candidate.safetyRatings?.some((rating) => rating.blocked) ||
      ['SAFETY', 'RECITATION', 'BLOCKLIST', 'PROHIBITED_CONTENT', 'SPII', 'IMAGE_SAFETY'].includes(
        candidate.finishReason,
      )
    )
      throw new Error('MODEL_REFUSAL');
    if (candidate.finishReason !== 'STOP') throw new Error('MODEL_INCOMPLETE');
    if (
      candidate.content.parts.some((part) =>
        [
          part.functionCall,
          part.functionResponse,
          part.executableCode,
          part.codeExecutionResult,
          part.toolCall,
          part.toolResponse,
        ].some((value) => value !== undefined),
      )
    )
      throw new Error('MODEL_UNEXPECTED_TOOL');
    return responseText(
      candidate.content.parts
        .filter((part) => !part.thought)
        .map((part) => part.text ?? '')
        .join(''),
    );
  }
  if (protocol === 'anthropic') {
    if (record.stop_reason === 'refusal') throw new Error('MODEL_REFUSAL');
    if (record.stop_reason !== 'end_turn') throw new Error('MODEL_INCOMPLETE');
    const content = textBlocks.parse(record.content);
    if (content.some((part) => !['text', 'thinking', 'redacted_thinking'].includes(part.type)))
      throw new Error('MODEL_UNEXPECTED_TOOL');
    return responseText(
      content
        .filter((part) => part.type === 'text')
        .map((part) => part.text ?? '')
        .join(''),
    );
  }
  if (protocol === 'cohere') {
    if (record.finish_reason !== 'COMPLETE') throw new Error('MODEL_INCOMPLETE');
    const message = z
      .object({ content: textBlocks, tool_calls: z.array(z.unknown()).optional() })
      .parse(record.message);
    if (message.tool_calls?.length) throw new Error('MODEL_UNEXPECTED_TOOL');
    if (message.content.some((part) => part.type === 'refusal')) throw new Error('MODEL_REFUSAL');
    if (message.content.some((part) => part.type !== 'text')) throw new Error('MODEL_UNEXPECTED_TOOL');
    return responseText(
      message.content
        .filter((part) => part.type === 'text')
        .map((part) => part.text ?? '')
        .join(''),
    );
  }
  const choices = z
    .array(
      z.object({
        finish_reason: z.string(),
        message: z.object({
          content: z.string(),
          refusal: z.string().nullable().optional(),
          tool_calls: z.array(z.unknown()).optional(),
          function_call: z.unknown().optional(),
        }),
      }),
    )
    .length(1)
    .parse(record.choices);
  const choice = choices[0]!;
  if (choice.message.refusal || choice.finish_reason === 'content_filter') throw new Error('MODEL_REFUSAL');
  if (choice.finish_reason !== 'stop') throw new Error('MODEL_INCOMPLETE');
  if (choice.message.tool_calls?.length || choice.message.function_call)
    throw new Error('MODEL_UNEXPECTED_TOOL');
  return responseText(choice.message.content);
}
