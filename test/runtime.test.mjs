import test from "node:test"
import assert from "node:assert/strict"
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createHmac } from "node:crypto"
import { BASE, createRuntime, encryptToken, decryptToken, readCredential, signature, localKey, parseLocalKey, validateBase } from "../runtime.mjs"
import { CodeFreeOAuthPlugin } from "../opencode.mjs"

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })
const refreshed = (suffix = "new") => json({ x_cf_token: `access-${suffix}`, x_cf_refresh_token: `refresh-${suffix}`, expires_in: 7200, refresh_token_expires_in: 604800 })
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), "magpie-codefree-test-"))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const path = join(dir, "codefree.json")
  await writeFile(path, JSON.stringify({ version: 2, userId: "123", encryptedRefreshCfToken: encryptToken("refresh-old"), refreshCfTokenExpiresAt: Date.now() + 86400000, baseUrlSnapshot: BASE }))
  return { path, userId: "123" }
}

test("AES-GCM roundtrip, tampering fails without leaking token", () => {
  const encrypted = encryptToken("fake-secret-token")
  assert.equal(decryptToken(encrypted), "fake-secret-token")
  const parts = encrypted.split(":"); parts[2] = Buffer.from("bad ciphertext").toString("base64")
  assert.throws(() => decryptToken(parts.join(":")), /无法读取/)
  assert.throws(() => decryptToken("v3:bad"), /无法读取/)
})

test("signature follows CodeFree-O's newline canonicalization", () => {
  const actual = signature("post", "client", 123, "nonce")
  const expected = createHmac("sha256", Buffer.from("HJhzHSFDctmDwSiXLdiidecX8p1uBmG2HHbTf5rD9n4=", "base64")).update("POST\nclient\n123\nnonce").digest("base64")
  assert.equal(actual["X-Cf-Signature"], expected)
})

test("local references pin identity, reject untrusted upstreams", async (t) => {
  const ref = await fixture(t)
  assert.deepEqual(parseLocalKey({ type: "api", key: localKey(ref.path, ref.userId) }), ref)
  assert.throws(() => parseLocalKey({ type: "api", key: "sk-user-secret" }), /请先连接/)
  await assert.rejects(readCredential(ref.path, "456"), /账号已改变/)
  for (const url of ["http://www.srdcloud.cn", "https://evil.example", "https://www.srdcloud.cn@evil.example", BASE + "/nested", BASE + "?token=x"]) assert.throws(() => validateBase(url))
})

test("concurrent model discovery refreshes once and persists rotated encrypted token", async (t) => {
  const ref = await fixture(t)
  let refreshes = 0, catalogs = 0
  const runtime = createRuntime({ fetchImpl: async (url, init) => {
    if (url.includes("access_token")) {
      refreshes++
      assert.equal(init.body.get("grant_type"), "refresh_x_cf_token")
      assert.equal(init.body.get("x_cf_refresh_token"), "refresh-old")
      await new Promise((r) => setTimeout(r, 20))
      return refreshed()
    }
    catalogs++
    assert.equal(init.headers.get("x-cf-token"), "access-new")
    assert.equal(init.headers.get("userid"), "123")
    assert.equal(init.redirect, "error")
    return json({ optResult: 0, data: [{ modelName: "live-model", displayName: "Live model", maxTokens: 100, maxOutputTokens: 20 }] })
  } })
  const results = await Promise.all([runtime.models(ref), runtime.models(ref), runtime.models(ref)])
  assert.equal(refreshes, 1); assert.equal(catalogs, 3)
  assert.equal(results[0]["live-model"].limit.context, 120)
  const saved = JSON.parse(await readFile(ref.path, "utf8"))
  assert.equal(decryptToken(saved.encryptedRefreshCfToken), "refresh-new")
  assert.equal(saved.userId, "123"); assert.equal(saved.cfToken, undefined)
  assert.ok(!JSON.stringify(saved).includes("refresh-new"))
})

test("chat remaps endpoint, strips foreign credentials and preserves tools and SSE byte-for-byte", async (t) => {
  const ref = await fixture(t)
  const wire = 'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"echo","arguments":"{}"}}]}}]}\n\ndata: [DONE]\n\n'
  const body = { model: "live-model", stream: true, messages: [{ role: "user", content: "hello" }], tools: [{ type: "function", function: { name: "echo", parameters: { type: "object", properties: {} } } }] }
  const runtime = createRuntime({ fetchImpl: async (url, init) => {
    if (url.includes("access_token")) return refreshed()
    assert.equal(url, BASE + "/api/acbackend/codechat/v1/completions")
    assert.deepEqual(JSON.parse(init.body), body)
    assert.equal(init.headers.get("authorization"), null)
    assert.equal(init.headers.get("cookie"), null)
    assert.equal(init.headers.get("apikey"), null)
    assert.equal(init.headers.get("x-cf-token"), "access-new")
    assert.equal(init.headers.get("modelname"), "live-model")
    assert.equal(init.headers.get("sessionid"), "conversation-123")
    assert.equal(init.headers.get("subservice"), "codefree_o_chat")
    return new Response(wire, { headers: { "content-type": "text/event-stream" } })
  } })
  const response = await runtime.chat(ref, new Request("https://placeholder.invalid/v1/chat/completions", { method: "POST", headers: { authorization: "Bearer foreign", cookie: "foreign", apikey: "foreign", "x-cf-token": "foreign", "x-session-affinity": "conversation-123" }, body: JSON.stringify(body) }))
  assert.equal(await response.text(), wire)
  await assert.rejects(runtime.chat(ref, "https://placeholder.invalid/responses", { method: "POST", body: "{}" }), /仅支持/)
})

test("401 retries once with a new token; quota 429 is not refreshed", async (t) => {
  const ref = await fixture(t)
  let refreshes = 0, calls = 0
  const runtime = createRuntime({ fetchImpl: async (url) => {
    if (url.includes("access_token")) return refreshed(String(++refreshes))
    calls++
    return calls === 1 ? json({ error: "expired" }, 401) : json({ error: "quota" }, 429)
  } })
  const res = await runtime.chat(ref, BASE + "/chat/completions", { method: "POST", body: JSON.stringify({ model: "live-model", messages: [] }) })
  assert.equal(res.status, 429); assert.equal(calls, 2); assert.equal(refreshes, 2)
})

test("failed refresh never erases or changes CLI credentials", async (t) => {
  const ref = await fixture(t)
  const before = await readFile(ref.path, "utf8")
  const runtime = createRuntime({ fetchImpl: async () => json({ error: "invalid" }, 401) })
  await assert.rejects(runtime.token(ref), /HTTP 401/)
  assert.equal(await readFile(ref.path, "utf8"), before)
})

test("missing/expired credentials make no network requests; plugin shape loads offline", async (t) => {
  const ref = await fixture(t)
  const saved = JSON.parse(await readFile(ref.path, "utf8")); saved.refreshCfTokenExpiresAt = 0
  await writeFile(ref.path, JSON.stringify(saved))
  const runtime = createRuntime({ fetchImpl: () => { throw new Error("must not send") } })
  await assert.rejects(runtime.token(ref), /已过期/)
  const hooks = await CodeFreeOAuthPlugin()
  const cfg = {}; await hooks.config(cfg)
  assert.equal(cfg.provider["codefree-o"].npm, "@ai-sdk/openai-compatible")
  assert.equal(hooks.auth.methods[0].type, "oauth")
  assert.deepEqual(await hooks.auth.loader(async () => undefined), {})
  assert.deepEqual(await hooks.provider.models({ models: {} }), {})
})
