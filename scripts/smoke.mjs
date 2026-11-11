// Uses the real logged-in account. Model requests consume a little quota.
// Never print credentials, auth results, headers or raw error responses.
import { authPath, readCredential, createRuntime, BASE } from "../runtime.mjs"
const path = authPath()
const cred = await readCredential(path)
const ref = { path, userId: cred.userId }
const runtime = createRuntime()
const models = await runtime.models(ref)
console.log("Live catalog:", Object.keys(models).join(", "))
if (!process.argv.includes("--chat") && !process.argv.includes("--tools")) process.exit(0)
const model = Object.keys(models).find((m) => /Qwen/i.test(m)) || Object.keys(models)[0]
const response = await runtime.chat(ref, BASE + "/v1/chat/completions", {
  method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(60000),
  body: JSON.stringify({ model, stream: true, max_tokens: 64, thinking: { type: "disabled" }, messages: [{ role: "user", content: "Reply only OK." }] }),
})
console.log("Chat HTTP:", response.status, "Content-Type:", response.headers.get("content-type"))
if (!response.ok) { await response.body?.cancel(); process.exit(1) }
const text = await response.text()
let content = "", reasoning = "", chunks = 0, done = false
for (const line of text.split(/\r?\n/)) {
  if (!line.startsWith("data:")) continue
  const value = line.slice(5).trim()
  if (value === "[DONE]") { done = true; continue }
  try {
    const data = JSON.parse(value); chunks++
    content += data.choices?.[0]?.delta?.content || ""
    reasoning += data.choices?.[0]?.delta?.reasoning_content || ""
  } catch {}
}
console.log(JSON.stringify({ model, chunks, done, content: content.slice(0, 100), reasoningCharacters: reasoning.length }))
if (!done || !chunks || (!content && !reasoning)) process.exit(1)
if (process.argv.includes("--tools")) {
  const messages = [{ role: "user", content: "Call echo with text OK. Do not answer without calling echo." }]
  const tools = [{ type: "function", function: { name: "echo", description: "Echo text", parameters: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } } }]
  const call = (payload) => runtime.chat(ref, BASE + "/v1/chat/completions", {
    method: "POST", signal: AbortSignal.timeout(60000),
    body: JSON.stringify({ model, stream: false, max_tokens: 128, thinking: { type: "disabled" }, ...payload }),
  })
  const first = await call({ messages, tools, tool_choice: { type: "function", function: { name: "echo" } } })
  if (!first.ok) { console.log("Tool call HTTP:", first.status); await first.body?.cancel(); process.exit(1) }
  const data = await first.json()
  const message = data.choices?.[0]?.message
  const toolCall = message?.tool_calls?.[0]
  if (!toolCall?.id || toolCall.function?.name !== "echo") throw new Error("Upstream did not return the requested tool call")
  const args = JSON.parse(toolCall.function.arguments)
  console.log("Actual tool call:", toolCall.function.name, "arguments valid:", typeof args.text === "string")
  messages.push(message, { role: "tool", tool_call_id: toolCall.id, content: JSON.stringify({ text: args.text }) })
  const followup = await call({ messages })
  if (!followup.ok) { console.log("Tool result follow-up HTTP:", followup.status); await followup.body?.cancel(); process.exit(1) }
  const answer = await followup.json()
  const result = answer.choices?.[0]?.message?.content
  console.log("Tool result follow-up:", JSON.stringify({ status: followup.status, content: result?.slice(0, 80) }))
  if (!result) throw new Error("Tool follow-up returned no content")
}
