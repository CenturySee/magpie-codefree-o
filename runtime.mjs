// Protocol observed in the user's installed @srdcloud/codefree-o 1.10.1.
// No user credentials belong in this module or the package.
import { createHash, createHmac, createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto"
import { readFile, writeFile, rename, unlink, open } from "node:fs/promises"
import { homedir } from "node:os"
import { join, resolve } from "node:path"

export const ID = "codefree-o"
export const BASE = "https://www.srdcloud.cn"
export const VERSION = "1.10.1"
const TOKEN_PATH = "/api/usercenterbackend/oauth/access_token"
const CHAT_PATH = "/api/acbackend/codechat/v1/completions"
const SEED = "codefree-o-refresh-token-local-encryption-key-v1"
// Public-client constants shipped with CodeFree-O, not the user's credentials.
const SIGNING_KEY = "HJhzHSFDctmDwSiXLdiidecX8p1uBmG2HHbTf5rD9n4="
const CLIENTS = {
  "https://www.srdcloud.cn": ["2542334461226y3rzqmr", "254233446135xuMOKaXTmgNMby4f42Ae7DRhEBAe"],
  "https://dev.srdcloud.cn": ["2538b593b435ordz03y5", "2538b593b438oyhwJqAfwlLD6Piz3LVTdpBTCTH5"],
  "https://test.srdcloud.cn": ["253b1906b368ack1rfoh", "253b1906b377WdoIMBvACC7iVemSnNXTKfOshlAb"],
}
const sessions = new Map()
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export function authPath(env = process.env, home = homedir()) {
  return resolve(env.MAGPIE_CODEFREE_AUTH_FILE || env.OPENCODE_CODEFREE_AUTH_FILE || join(home, ".codefree-o", ".local", "share", "codefree.json"))
}

export function validateBase(value = BASE) {
  const url = new URL(value)
  if (!CLIENTS[url.origin] || url.pathname !== "/" || url.search || url.hash || url.username || url.password) {
    throw new Error("CodeFree 上游地址不受支持；仅支持官方生产、dev、test 站点")
  }
  return url.origin
}

export function encryptToken(token) {
  const nonce = randomBytes(12)
  const cipher = createCipheriv("aes-256-gcm", createHash("sha256").update(SEED).digest(), nonce)
  const data = Buffer.concat([cipher.update(token, "utf8"), cipher.final()])
  return ["v1", nonce.toString("base64"), data.toString("base64"), cipher.getAuthTag().toString("base64")].join(":")
}

export function decryptToken(value) {
  try {
    const [version, nonce, data, tag, extra] = String(value).split(":")
    if (version !== "v1" || !nonce || !data || !tag || extra !== undefined) throw new Error()
    const decipher = createDecipheriv("aes-256-gcm", createHash("sha256").update(SEED).digest(), Buffer.from(nonce, "base64"))
    decipher.setAuthTag(Buffer.from(tag, "base64"))
    return Buffer.concat([decipher.update(Buffer.from(data, "base64")), decipher.final()]).toString("utf8")
  } catch {
    throw new Error("无法读取 CodeFree 刷新令牌，请在 codefree-o 中重新登录（仅支持 v2 登录文件）")
  }
}

export function signature(method, appId, timestamp = Math.floor(Date.now() / 1000), nonce = randomUUID()) {
  const text = [method.toUpperCase(), appId, String(timestamp), nonce].join("\n")
  return {
    "X-Cf-AppId": appId,
    "X-Cf-Timestamp": String(timestamp),
    "X-Cf-Nonce": nonce,
    "X-Cf-Signature": createHmac("sha256", Buffer.from(SIGNING_KEY, "base64")).update(text).digest("base64"),
  }
}

export async function readCredential(path, expectedUser) {
  let data
  try { data = JSON.parse(await readFile(path, "utf8")) }
  catch { throw new Error("未读到 CodeFree-O 登录文件，请先启动 codefree-o 并完成登录") }
  if (data.version !== 2 || !data.userId || !data.encryptedRefreshCfToken) throw new Error("CodeFree 登录文件格式不受支持，请用 codefree-o 1.10.1 重新登录")
  if (expectedUser && String(data.userId) !== String(expectedUser)) throw new Error("CodeFree 本地账号已改变，请在 magpie 中重新连接该账号")
  const base = validateBase(data.baseUrlSnapshot || BASE)
  if (!Number.isFinite(data.refreshCfTokenExpiresAt) || data.refreshCfTokenExpiresAt <= Date.now()) throw new Error("CodeFree 登录已过期，请在 codefree-o 中重新登录")
  return { data, base, refresh: decryptToken(data.encryptedRefreshCfToken), userId: String(data.userId) }
}

// The stored 'key' is a local-file reference, not a bearer token. It also pins
// the account so signing into another CLI account cannot silently reroute it.
export function localKey(path, userId) {
  return "codefree-o-local:" + Buffer.from(JSON.stringify({ path: resolve(path), userId: String(userId) })).toString("base64url")
}

export function parseLocalKey(auth) {
  try {
    if (auth?.type !== "api" || !auth.key?.startsWith("codefree-o-local:")) throw new Error()
    const value = JSON.parse(Buffer.from(auth.key.slice("codefree-o-local:".length), "base64url").toString("utf8"))
    if (typeof value.path !== "string" || !value.path || typeof value.userId !== "string" || !value.userId) throw new Error()
    return { path: resolve(value.path), userId: value.userId }
  } catch { throw new Error("请先连接 CodeFree-O：读取本机 CLI 登录态") }
}

async function withFileLock(path, fn) {
  // Coordinates plugin hosts. CodeFree-O itself does not honour this lock;
  // compare the source file before saving and recover rotated tokens on 401.
  const lock = path + ".magpie.lock"
  let handle
  for (let n = 0; n < 150; n++) {
    try { handle = await open(lock, "wx", 0o600); break }
    catch (error) { if (error.code !== "EEXIST") throw error; await sleep(200) }
  }
  if (!handle) throw new Error("CodeFree 登录文件正由其他插件进程刷新，或上次异常退出留下 .magpie.lock；请检查后重试")
  try { return await fn() }
  finally { await handle.close(); await unlink(lock) }
}

async function saveRotation(path, previous, next) {
  const latest = await readCredential(path, previous.userId)
  if (latest.data.encryptedRefreshCfToken !== previous.data.encryptedRefreshCfToken) return false
  const temporary = path + ".magpie-" + randomUUID() + ".tmp"
  try {
    await writeFile(temporary, JSON.stringify({
      ...latest.data,
      encryptedRefreshCfToken: encryptToken(next.refresh),
      refreshCfTokenExpiresAt: next.refreshExpires,
    }, null, 2) + "\n", { mode: 0o600, flag: "wx" })
    await rename(temporary, path)
  } finally { await unlink(temporary).catch(() => {}) }
  return true
}

export function createRuntime({ fetchImpl = globalThis.fetch, version = process.env.MAGPIE_CODEFREE_VERSION || VERSION } = {}) {
  // Separate caches for injected test transports; production shares one cache.
  const cache = fetchImpl === globalThis.fetch ? sessions : new Map()

  async function token(ref, staleAccess) {
    const cacheKey = JSON.stringify(ref)
    const disk = await readCredential(ref.path, ref.userId)
    let state = cache.get(cacheKey)
    if (!state) { state = {}; cache.set(cacheKey, state) }
    if (state.pending) return state.pending
    if (state.value && state.value.diskToken === disk.data.encryptedRefreshCfToken && state.value.expires > Date.now() + 60000 && state.value.access !== staleAccess) return state.value
    state.pending = withFileLock(ref.path, async () => {
      for (let attempt = 0; attempt < 2; attempt++) {
        const cred = await readCredential(ref.path, ref.userId)
        const [appId, clientSecret] = CLIENTS[cred.base]
        const res = await fetchImpl(cred.base + TOKEN_PATH, {
          method: "POST", redirect: "error", signal: AbortSignal.timeout(20000),
          headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
          body: new URLSearchParams({ grant_type: "refresh_x_cf_token", client_id: appId, client_secret: clientSecret, x_cf_refresh_token: cred.refresh }),
        })
        if (!res.ok) {
          const updated = await readCredential(ref.path, ref.userId)
          if (attempt === 0 && [400, 401].includes(res.status) && updated.refresh !== cred.refresh) continue
          throw Object.assign(new Error(`CodeFree 令牌刷新失败（HTTP ${res.status}），请在 CLI 重新登录后重试`), { status: res.status })
        }
        const body = res.headers.get("content-type")?.includes("json") ? await res.json() : Object.fromEntries(new URLSearchParams(await res.text()))
        const access = body.x_cf_token || body.cf_token || (body.token_type === "cf_token" && body.access_token)
        const refresh = body.x_cf_refresh_token || body.refresh_token || body.refresh_cf_token || body.cf_token_refresh_token
        const responseUser = body.id ?? body.userId ?? body.user_id ?? body.uid
        if (responseUser && String(responseUser) !== ref.userId) throw new Error("CodeFree 刷新结果账号不匹配")
        if (typeof access !== "string" || !access || typeof refresh !== "string" || !refresh) throw new Error("CodeFree 令牌接口返回格式已变化")
        const seconds = (v, fallback) => Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : fallback
        const next = {
          base: cred.base, userId: ref.userId, appId, access, refresh,
          expires: Date.now() + seconds(body.x_cf_token_expires_in ?? body.cf_token_expires_in ?? body.expires_in, 7200) * 1000,
          refreshExpires: Date.now() + seconds(body.x_cf_refresh_token_expires_in ?? body.refresh_token_expires_in ?? body.refresh_cf_token_expires_in ?? body.cf_token_refresh_token_expires_in, 604800) * 1000,
        }
        if (!await saveRotation(ref.path, cred, next)) continue
        const saved = await readCredential(ref.path, ref.userId)
        state.value = { ...next, diskToken: saved.data.encryptedRefreshCfToken }
        return state.value
      }
      throw new Error("CodeFree CLI 正在同时更新登录态，请稍后重试")
    }).finally(() => { state.pending = undefined })
    return state.pending
  }

  async function signedRequest(ref, path, init = {}) {
    const send = (cred) => {
      const headers = new Headers(init.headers)
      for (const key of [...headers.keys()]) if (/^(authorization|apikey|accesstoken|userid|projectid|cookie|host|content-length)$|^x-cf-/i.test(key)) headers.delete(key)
      headers.set("X-Cf-Token", cred.access)
      headers.set("userId", cred.userId)
      headers.set("projectId", "0")
      headers.set("clientType", "codefree-o")
      headers.set("clientVersion", version)
      for (const [key, value] of Object.entries(signature(init.method || "GET", cred.appId))) headers.set(key, value)
      return fetchImpl(cred.base + path, { ...init, headers, redirect: "error" })
    }
    const cred = await token(ref)
    let res = await send(cred)
    if (res.status === 401) {
      await res.body?.cancel()
      res = await send(await token(ref, cred.access))
    }
    return res
  }

  async function models(ref) {
    const res = await signedRequest(ref, `/api/acbackend/modelmgr/v1/clients/codefree-o/versions/${encodeURIComponent(version)}`, { signal: AbortSignal.timeout(20000) })
    if (!res.ok) throw new Error(`CodeFree 模型目录请求失败（HTTP ${res.status}）`)
    const body = await res.json()
    if (body.optResult !== 0 || !Array.isArray(body.data)) throw new Error("CodeFree 模型目录返回格式已变化")
    return Object.fromEntries(body.data.filter((m) => typeof m.modelName === "string" && m.modelName).map((m) => [m.modelName, modelRow(m)]))
  }

  async function chat(ref, input, init) {
    const req = new Request(input, init)
    // Never forward authentication to a URL supplied by the caller.
    if (!new URL(req.url).pathname.endsWith("/chat/completions") || req.method !== "POST") throw new Error("CodeFree 插件仅支持 POST /chat/completions")
    const body = await req.text()
    const parsed = JSON.parse(body)
    if (typeof parsed.model !== "string" || !parsed.model) throw new Error("CodeFree 请求缺少模型名称")
    const headers = new Headers(req.headers)
    headers.set("content-type", "application/json")
    headers.set("modelName", parsed.model)
    headers.set("subService", "codefree_o_chat")
    headers.set("codefreeClient", "codefreeo")
    headers.set("sessionId", headers.get("sessionId") || headers.get("x-session-affinity") || randomUUID())
    return signedRequest(ref, CHAT_PATH, { method: "POST", headers, body, signal: req.signal })
  }
  return { token, models, chat }
}

export function modelRow(m) {
  const image = m.modelType === "multimodal"
  const input = Number(m.maxTokens) || 80000, output = Number(m.maxOutputTokens) || 8000
  return {
    id: m.modelName, name: m.displayName || m.modelName,
    limit: { context: Number(m.maxTotalTokens) || input + output, output },
    reasoning: true, tool_call: true, attachment: image,
    interleaved: { field: "reasoning_content" },
    modalities: { input: image ? ["text", "image"] : ["text"], output: ["text"] },
    ...(m.accessMode === undefined ? {} : { options: { accessMode: m.accessMode } }),
  }
}
