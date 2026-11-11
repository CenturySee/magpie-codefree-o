// End-to-end check in an isolated magpie profile, never the user's settings.
import { spawn } from "node:child_process"
import { mkdtemp, mkdir, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { resolve, join } from "node:path"
import { fileURLToPath } from "node:url"
import { authPath } from "../runtime.mjs"

const binary = process.env.MAGPIE_BINARY || join(process.env.LOCALAPPDATA, "Programs", "magpie", "magpie.com")
const root = resolve(fileURLToPath(new URL("..", import.meta.url)))
const sandbox = await mkdtemp(join(tmpdir(), "magpie-codefree-e2e-"))
const env = {
  ...process.env, USERPROFILE: sandbox,
  XDG_CONFIG_HOME: join(sandbox, ".config"), XDG_CACHE_HOME: join(sandbox, ".cache"),
  MAGPIE_CODEFREE_AUTH_FILE: authPath(), MAGPIE_ADDR: "127.0.0.1:13425",
}
await mkdir(env.XDG_CONFIG_HOME, { recursive: true })
const run = (args) => new Promise((resolveResult, reject) => {
  const child = spawn(binary, args, { env, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] })
  let output = ""
  child.stdout.on("data", (b) => { output += b }); child.stderr.on("data", (b) => { output += b })
  child.stdin.end()
  const timer = setTimeout(() => { child.kill(); reject(new Error(`magpie ${args[0]} timed out`)) }, 60000)
  child.on("error", reject)
  child.on("close", (code) => { clearTimeout(timer); resolveResult({ code, output }) })
})
let server
try {
  for (const args of [["plugin", "add", root], ["plugin", "login", "codefree-o"]]) {
    const result = await run(args)
    console.log(`magpie ${args.slice(0, 3).join(" ")}: exit ${result.code}`)
    if (result.code !== 0) {
      // No auth body/header/token is printed; this CLI step has only local refs.
      console.log(result.output.replaceAll(sandbox, "<sandbox>").slice(-1800))
      throw new Error("magpie integration failed")
    }
  }
  server = spawn(binary, ["serve"], { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] })
  let logs = ""
  server.stdout.on("data", (b) => { logs += b }); server.stderr.on("data", (b) => { logs += b })
  let catalog
  for (let i = 0; i < 100; i++) {
    try {
      const res = await fetch("http://127.0.0.1:13425/v1/models")
      if (res.ok) { catalog = await res.json(); if (catalog.data?.some((m) => m.id.startsWith("codefree-o"))) break }
    } catch {}
    await new Promise((r) => setTimeout(r, 300))
  }
  const models = catalog?.data?.filter((m) => m.id.startsWith("codefree-o")) || []
  console.log("magpie gateway catalog:", models.map((m) => m.id).join(", "))
  if (!models.length) throw new Error("magpie gateway has no CodeFree models")
  const model = models.find((m) => /Qwen/i.test(m.id))?.id || models[0].id
  const res = await fetch("http://127.0.0.1:13425/v1/chat/completions", {
    method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(60000),
    body: JSON.stringify({ model, stream: true, max_tokens: 64, thinking: { type: "disabled" }, messages: [{ role: "user", content: "Reply only OK." }] }),
  })
  console.log("magpie gateway chat HTTP:", res.status)
  if (!res.ok) { await res.body?.cancel(); throw new Error("magpie gateway chat failed") }
  const wire = await res.text()
  let content = "", chunks = 0
  for (const line of wire.split(/\r?\n/)) if (line.startsWith("data:")) {
    try { const data = JSON.parse(line.slice(5)); chunks++; content += data.choices?.[0]?.delta?.content || "" } catch {}
  }
  console.log(JSON.stringify({ model, chunks, done: wire.includes("[DONE]"), content: content.slice(0, 80) }))
  if (!chunks || !wire.includes("[DONE]") || !content) throw new Error("magpie SSE verification failed")
} finally {
  if (server && server.exitCode === null) {
    // The .com launcher starts an .exe child on Windows; stop that tree too.
    if (process.platform === "win32") await new Promise((r) => { const killer = spawn("taskkill", ["/PID", String(server.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" }); killer.on("close", r) })
    else server.kill()
  }
  await rm(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
}
