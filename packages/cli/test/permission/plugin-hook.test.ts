import { afterAll, afterEach, beforeAll, describe, expect } from "bun:test"
import { Cause, Effect, Exit, Fiber, Layer } from "effect"
import { existsSync, readFileSync } from "fs"
import fs from "fs/promises"
import os from "os"
import path from "path"
import { pathToFileURL } from "url"
import { Bus } from "../../src/bus"
import * as CrossSpawnSpawner from "../../src/effect/cross-spawn-spawner"
import { Permission } from "../../src/permission"
import { Plugin } from "../../src/plugin"
import { Instance } from "../../src/project/instance"
import { MessageID, SessionID } from "../../src/session/schema"
import { provideTmpdirInstance } from "../fixture/fixture"
import { testEffect } from "../lib/effect"
import { Log } from "../../src/util"

void Log.init({ print: false })

afterEach(async () => {
  await Instance.disposeAll()
})

const bus = Bus.layer
const permission = Permission.layer.pipe(Layer.provide(bus))
const it = testEffect(Layer.mergeAll(permission, Plugin.defaultLayer, bus, CrossSpawnSpawner.defaultLayer))
const noPlugins = testEffect(Layer.mergeAll(permission, bus, CrossSpawnSpawner.defaultLayer))

// A config plugin, loaded through the real plugin service. It decides by the
// first pattern's prefix ("allow:", "ask:", "deny:", "deny-quietly:", anything
// else leaves the status alone) and records every call it gets.
let dir: string
let calls: string
let plugin: string

beforeAll(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), "mimocode-permission-ask-"))
  calls = path.join(dir, "calls.jsonl")
  const file = path.join(dir, "plugin.ts")
  await fs.writeFile(
    file,
    [
      `import fs from "fs"`,
      `export default async () => ({`,
      `  "permission.ask": async (input, output) => {`,
      `    fs.appendFileSync(${JSON.stringify(calls)}, JSON.stringify({ input, status: output.status }) + "\\n")`,
      `    const mode = input.patterns[0].split(":")[0]`,
      `    if (mode === "allow" || mode === "ask") output.status = mode`,
      `    if (mode === "deny" || mode === "deny-quietly") output.status = "deny"`,
      `    if (mode === "deny") output.reason = "it writes outside the project"`,
      `  },`,
      `})`,
    ].join("\n"),
  )
  plugin = pathToFileURL(file).href
})

afterAll(() => fs.rm(dir, { recursive: true, force: true }))

const withPlugin = <A, E, R>(self: () => Effect.Effect<A, E, R>) =>
  provideTmpdirInstance(self, { config: { plugin: [plugin] } })

/** What the plugin was given for requests with this pattern, in order. */
const seen = (pattern: string): { input: Record<string, unknown>; status: string }[] =>
  existsSync(calls)
    ? readFileSync(calls, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))
        .filter((call) => call.input.patterns[0] === pattern)
    : []

const allowRules: Permission.Ruleset = [{ permission: "bash", pattern: "*", action: "allow" }]
const askRules: Permission.Ruleset = [{ permission: "bash", pattern: "*", action: "ask" }]
const denyRules: Permission.Ruleset = [{ permission: "bash", pattern: "*", action: "deny" }]

// interactive: false makes an ask fail at once with DeniedError instead of
// waiting for a person.
const request = (
  pattern: string,
  ruleset: Permission.Ruleset,
  options: { permission?: string; interactive?: boolean } = {},
) => ({
  sessionID: SessionID.make("ses_test"),
  permission: options.permission ?? "bash",
  patterns: [pattern],
  metadata: {},
  always: [],
  tool: { messageID: MessageID.make("msg_test"), callID: "call_1" },
  ruleset,
  interactive: options.interactive ?? false,
})

const ask = (input: Parameters<Permission.Interface["ask"]>[0]) =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    return yield* permission.ask(input)
  })

const failure = <A, E, R>(self: Effect.Effect<A, E, R>) =>
  Effect.gen(function* () {
    const exit = yield* self.pipe(Effect.exit)
    if (Exit.isFailure(exit)) return Cause.squash(exit.cause)
    throw new Error("expected the permission request to fail")
  })

const waitForPending = (count: number) =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    for (let i = 0; i < 100; i++) {
      const list = yield* permission.list()
      if (list.length === count) return list
      yield* Effect.sleep("10 millis")
    }
    return yield* Effect.fail(new Error(`timed out waiting for ${count} pending permission request(s)`))
  })

describe.serial("Permission: the permission.ask plugin hook", () => {
  it.live("a plugin can allow what the rules ask about, and gets the request as permission.asked carries it", () =>
    withPlugin(() =>
      Effect.gen(function* () {
        yield* ask(request("allow:1", askRules))
        const [call] = seen("allow:1")
        expect(call.status).toBe("ask")
        expect(Object.keys(call.input).sort()).toEqual([
          "always",
          "metadata",
          "patterns",
          "permission",
          "sessionID",
          "tool",
        ])
        expect(call.input).toMatchObject({ permission: "bash", patterns: ["allow:1"], tool: { callID: "call_1" } })
      }),
    ),
  )

  it.live("a plugin can ask about what the rules allow, and the user is asked", () =>
    withPlugin(() =>
      Effect.gen(function* () {
        const fiber = yield* ask(request("ask:2", allowRules, { interactive: true })).pipe(Effect.forkScoped)
        const [pending] = yield* waitForPending(1)
        expect(pending).toMatchObject({ patterns: ["ask:2"], tool: { callID: "call_1" } })
        expect(seen("ask:2").map((call) => call.status)).toEqual(["allow"])
        const permission = yield* Permission.Service
        yield* permission.reply({ requestID: pending.id, reply: "once" })
        yield* Fiber.join(fiber)
      }),
    ),
  )

  it.live("a plugin can deny what the rules allow, and the model is told its reason", () =>
    withPlugin(() =>
      Effect.gen(function* () {
        const err = yield* failure(ask(request("deny:3", allowRules)))
        expect(err).toBeInstanceOf(Permission.CorrectedError)
        expect(err).toMatchObject({ feedback: "it writes outside the project" })
      }),
    ),
  )

  it.live("a deny without a reason still tells the model a plugin refused", () =>
    withPlugin(() =>
      Effect.gen(function* () {
        const err = yield* failure(ask(request("deny-quietly:4", allowRules)))
        expect(err).toBeInstanceOf(Permission.CorrectedError)
        expect(err).toMatchObject({ feedback: "A plugin refused this request." })
      }),
    ),
  )

  it.live("a ruleset deny wins: the plugin is not consulted", () =>
    withPlugin(() =>
      Effect.gen(function* () {
        expect(yield* failure(ask(request("allow:5", denyRules)))).toBeInstanceOf(Permission.DeniedError)
        expect(seen("allow:5")).toHaveLength(0)
      }),
    ),
  )

  it.live("a permission that always asks reaches the plugin but cannot be allowed by it", () =>
    withPlugin(() =>
      Effect.gen(function* () {
        const err = yield* failure(ask(request("allow:6", [], { permission: "bash_delete" })))
        expect(err).toBeInstanceOf(Permission.DeniedError)
        expect(seen("allow:6").map((call) => call.status)).toEqual(["ask"])
      }),
    ),
  )

  it.live("a plugin can deny a permission that always asks", () =>
    withPlugin(() =>
      Effect.gen(function* () {
        const err = yield* failure(ask(request("deny:7", [], { permission: "bash_delete" })))
        expect(err).toBeInstanceOf(Permission.CorrectedError)
      }),
    ),
  )

  it.live("a plugin that leaves the status alone changes nothing", () =>
    withPlugin(() =>
      Effect.gen(function* () {
        yield* ask(request("pass:8", allowRules))
        expect(yield* failure(ask(request("pass:8", askRules)))).toBeInstanceOf(Permission.DeniedError)
        expect(seen("pass:8").map((call) => call.status)).toEqual(["allow", "ask"])
      }),
    ),
  )

  noPlugins.live("without a plugin service, the rules decide as before", () =>
    provideTmpdirInstance(() =>
      Effect.gen(function* () {
        yield* ask(request("allow:9", allowRules))
        expect(yield* failure(ask(request("allow:9", askRules)))).toBeInstanceOf(Permission.DeniedError)
        expect(seen("allow:9")).toHaveLength(0)
      }),
    ),
  )
})
