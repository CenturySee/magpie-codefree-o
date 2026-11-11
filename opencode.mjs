import { ID, BASE, authPath, readCredential, localKey, parseLocalKey, createRuntime } from "./runtime.mjs"

export const CodeFreeOAuthPlugin = async () => {
  const runtime = createRuntime()
  return {
    config: async (cfg) => {
      cfg.provider ??= {}
      cfg.provider[ID] ??= {
        name: "CodeFree-O（本机登录）",
        npm: "@ai-sdk/openai-compatible",
        api: BASE + "/v1",
        models: {}, // Account-scoped live catalog, never invent available models.
      }
    },
    auth: {
      provider: ID,
      methods: [{
        type: "oauth",
        label: "读取本机 CodeFree-O CLI 登录态",
        async authorize() {
          const path = authPath()
          const cred = await readCredential(path)
          return {
            url: "", method: "auto",
            instructions: "已找到 CodeFree-O 本机登录态，正在连接…",
            callback: async () => {
              const ref = { path, userId: cred.userId }
              await runtime.token(ref)
              return { type: "success", key: localKey(path, cred.userId), accountId: cred.userId }
            },
          }
        },
      }],
      async loader(getAuth) {
        const auth = await getAuth()
        if (!auth) return {}
        const ref = parseLocalKey(auth)
        return { baseURL: BASE + "/v1", apiKey: "local-file", fetch: (input, init) => runtime.chat(ref, input, init) }
      },
    },
    provider: {
      id: ID,
      async models(provider, { auth } = {}) {
        if (!auth) return provider.models
        return runtime.models(parseLocalKey(auth))
      },
    },
  }
}
