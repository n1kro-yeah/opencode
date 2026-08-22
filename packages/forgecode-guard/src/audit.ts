import { createWriteStream, type WriteStream } from "node:fs"
import { mkdir, rename, stat } from "node:fs/promises"
import { dirname } from "node:path"
import { createHash } from "node:crypto"

export interface AuditEvent {
  readonly timestamp: string
  readonly type: string
  readonly sessionID?: string
  readonly tool?: string
  readonly callID?: string
  readonly effect?: string
  readonly reason?: string
  readonly data?: Readonly<Record<string, unknown>>
}

export class AuditLog {
  readonly path: string
  readonly maxBytes: number
  readonly maxFiles: number
  private stream: WriteStream | undefined
  private bytes = 0
  private rotating: Promise<void> | undefined

  constructor(path: string, maxBytes = 10 * 1024 * 1024, maxFiles = 5) {
    this.path = path
    this.maxBytes = maxBytes
    this.maxFiles = maxFiles
  }

  async open(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 })
    this.bytes = (await stat(this.path).catch(() => undefined))?.size ?? 0
    this.stream = createWriteStream(this.path, { flags: "a", mode: 0o600 })
  }

  write(event: Omit<AuditEvent, "timestamp">): void {
    if (this.stream === undefined) return
    const line = JSON.stringify({ timestamp: new Date().toISOString(), ...event, data: event.data === undefined ? undefined : sanitize(event.data) })
    this.bytes += Buffer.byteLength(line) + 1
    this.stream.write(`${line}\n`)
    if (this.bytes >= this.maxBytes) void this.rotate()
  }

  async close(): Promise<void> {
    await this.rotating
    const stream = this.stream
    this.stream = undefined
    if (stream !== undefined) await new Promise<void>((resolve) => stream.end(resolve))
  }

  private async rotate(): Promise<void> {
    if (this.rotating !== undefined) return this.rotating
    this.rotating = (async () => {
      const current = this.stream
      this.stream = undefined
      if (current !== undefined) await new Promise<void>((resolve) => current.end(resolve))
      for (let index = this.maxFiles - 1; index >= 1; index -= 1) await rename(`${this.path}.${index}`, `${this.path}.${index + 1}`).catch(() => undefined)
      await rename(this.path, `${this.path}.1`).catch(() => undefined)
      await this.open()
    })().finally(() => { this.rotating = undefined })
    return this.rotating
  }
}

function sanitize(value: unknown, key = ""): unknown {
  if (/(?:key|token|secret|password|authorization|credential)/i.test(key)) return "[REDACTED]"
  if (typeof value === "string") return value.length > 2000 ? `${value.slice(0, 2000)}…[TRUNCATED:${value.length}]` : value
  if (Array.isArray(value)) return value.map((item) => sanitize(item))
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, sanitize(child, childKey)]))
  return value
}

export function fingerprint(value: unknown): string { return createHash("sha256").update(JSON.stringify(sanitize(value))).digest("hex").slice(0, 20) }
