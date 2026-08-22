import { homedir } from "node:os"
import { isAbsolute, resolve } from "node:path"

export type Effect = "allow" | "ask" | "deny"
export type PermissionMode = "manual" | "accept-edits" | "plan" | "dont-ask" | "bypass"

export interface Rule {
  readonly effect: Effect
  readonly tool: string
  readonly pattern?: string
  readonly reason?: string
}

export interface GuardConfig {
  readonly mode: PermissionMode
  readonly rules: readonly Rule[]
  readonly protectedPaths: readonly string[]
  readonly allowedDomains: readonly string[]
  readonly deniedDomains: readonly string[]
  readonly maxOutputTokens: number
  readonly maxTemperature: number
  readonly redactToolOutput: boolean
  readonly audit: boolean
}

export interface Intent {
  readonly tool: string
  readonly args: Readonly<Record<string, unknown>>
  readonly cwd: string
}

export interface Decision {
  readonly effect: Effect
  readonly reason: string
  readonly matchedRule?: Rule
  readonly risk: readonly string[]
}

export const DEFAULT_GUARD_CONFIG: GuardConfig = {
  mode: "manual",
  rules: [
    { effect: "deny", tool: "read", pattern: "**/.env*", reason: "Environment secrets are protected" },
    { effect: "deny", tool: "read", pattern: "**/*credentials*", reason: "Credential files are protected" },
    { effect: "deny", tool: "bash", pattern: "regex:(?:^|\\s)(?:sudo|su|doas|pkexec)(?:\\s|$)", reason: "Privilege escalation is blocked" },
    { effect: "deny", tool: "bash", pattern: "regex:\\b(?:mkfs|shutdown|reboot|halt|poweroff)\\b", reason: "System-destructive command is blocked" },
    { effect: "ask", tool: "bash", pattern: "regex:\\b(?:git\\s+push|npm\\s+publish|docker\\s+push|kubectl\\s+apply|terraform\\s+apply)\\b", reason: "External side effect requires approval" },
    { effect: "allow", tool: "read" },
    { effect: "allow", tool: "glob" },
    { effect: "allow", tool: "grep" },
    { effect: "allow", tool: "list" },
  ],
  protectedPaths: ["~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "**/.env", "**/.env.*", "**/secrets/**", "**/*.pem", "**/*.key", "**/.git/config", "**/.git/hooks/**"],
  allowedDomains: [],
  deniedDomains: ["169.254.169.254", "metadata.google.internal", "metadata.aws.internal"],
  maxOutputTokens: 32768,
  maxTemperature: 1,
  redactToolOutput: true,
  audit: true,
}

export function mergeConfig(base: GuardConfig, override: unknown): GuardConfig {
  if (!isRecord(override)) return base
  return {
    mode: isMode(override.mode) ? override.mode : base.mode,
    rules: Array.isArray(override.rules) ? [...base.rules, ...override.rules.filter(isRule)] : base.rules,
    protectedPaths: stringArray(override.protectedPaths, base.protectedPaths),
    allowedDomains: stringArray(override.allowedDomains, base.allowedDomains),
    deniedDomains: stringArray(override.deniedDomains, base.deniedDomains),
    maxOutputTokens: positiveInteger(override.maxOutputTokens, base.maxOutputTokens),
    maxTemperature: boundedNumber(override.maxTemperature, base.maxTemperature, 0, 2),
    redactToolOutput: typeof override.redactToolOutput === "boolean" ? override.redactToolOutput : base.redactToolOutput,
    audit: typeof override.audit === "boolean" ? override.audit : base.audit,
  }
}

export class PolicyEngine {
  readonly config: GuardConfig

  constructor(config: GuardConfig) {
    this.config = config
  }

  decide(intent: Intent): Decision {
    const risk = classifyRisk(intent)
    const hard = this.hardBoundary(intent, risk)
    if (hard !== undefined) return hard
    if (this.config.mode === "bypass") return { effect: "allow", reason: "Bypass mode", risk }
    if (this.config.mode === "plan" && mutates(intent.tool, risk)) return { effect: "deny", reason: "Plan mode is read-only", risk }
    const matching = this.config.rules.filter((rule) => matchesRule(rule, intent))
    for (const effect of ["deny", "ask", "allow"] as const) {
      const rule = matching.find((item) => item.effect === effect)
      if (rule !== undefined) {
        if (this.config.mode === "dont-ask" && effect === "ask") return { effect: "deny", reason: "dont-ask mode converts prompts to denials", matchedRule: rule, risk }
        return { effect, reason: rule.reason ?? `${effect} rule matched`, matchedRule: rule, risk }
      }
    }
    if (this.config.mode === "accept-edits" && isEditTool(intent.tool)) return { effect: "allow", reason: "Edits are accepted for this session", risk }
    if (readOnly(intent.tool, risk)) return { effect: "allow", reason: "Read-only operation", risk }
    if (this.config.mode === "dont-ask") return { effect: "deny", reason: "Operation is not pre-approved", risk }
    return { effect: "ask", reason: summarizeRisk(risk), risk }
  }

  private hardBoundary(intent: Intent, risk: readonly string[]): Decision | undefined {
    const subject = subjectFor(intent)
    if (risk.includes("privileged")) return { effect: "deny", reason: "Privilege escalation is blocked", risk }
    if (risk.includes("catastrophic")) return { effect: "deny", reason: "Catastrophic command is blocked", risk }
    const path = extractPath(intent.args)
    if (path !== undefined && this.config.protectedPaths.some((pattern) => globMatch(normalizePath(path, intent.cwd), expandHome(pattern)))) {
      return { effect: isEditTool(intent.tool) ? "deny" : "ask", reason: `Protected path: ${path}`, risk }
    }
    for (const domain of domains(subject)) {
      if (this.config.deniedDomains.some((pattern) => domainMatches(domain, pattern))) return { effect: "deny", reason: `Network destination is denied: ${domain}`, risk }
      if (this.config.allowedDomains.length > 0 && !this.config.allowedDomains.some((pattern) => domainMatches(domain, pattern))) return { effect: "ask", reason: `Network destination is not allowlisted: ${domain}`, risk }
    }
    return undefined
  }
}

export function classifyRisk(intent: Intent): string[] {
  const risks = new Set<string>()
  if (isEditTool(intent.tool)) risks.add("write")
  if (/^(?:read|glob|grep|list|lsp|git_status|git_diff)/i.test(intent.tool)) risks.add("read")
  const subject = subjectFor(intent)
  if (intent.tool === "bash" || intent.tool === "shell") {
    if (/(?:^|\s)(?:sudo|su|doas|pkexec)(?:\s|$)/i.test(subject)) risks.add("privileged")
    if (/\b(?:mkfs|shutdown|reboot|halt|poweroff)\b|:\(\)\s*\{\s*:\|:&\s*\};:/i.test(subject)) risks.add("catastrophic")
    if (/\b(?:rm|rmdir|shred|truncate|git\s+reset\s+--hard|git\s+clean\s+-\w*f|git\s+push\s+.*--force)\b/i.test(subject)) risks.add("destructive")
    if (/(^|[^<])>>?\s*[^&]/.test(subject) || /\b(?:cp|mv|mkdir|touch|tee|sed\s+-i|git\s+(?:add|commit|checkout|switch|restore|merge|rebase)|npm\s+install|pip\s+install)\b/i.test(subject)) risks.add("write")
    if (/\b(?:curl|wget|ssh|scp|git\s+(?:push|pull|fetch)|npm\s+publish|docker\s+push|kubectl\s+apply)\b/i.test(subject)) risks.add("network")
    if (/`[^`]*`|\$\([^)]*\)|\beval\b|\bexec\b|\bxargs\b/.test(subject)) risks.add("dynamic")
    if (/(?:curl|wget)[^|\n]*\|\s*(?:sh|bash|zsh|python|node)\b/i.test(subject)) risks.add("remote-execution")
  }
  if (domains(subject).length > 0) risks.add("network")
  if (risks.size === 0) risks.add("unknown")
  return [...risks]
}

function matchesRule(rule: Rule, intent: Intent): boolean {
  if (!toolMatches(rule.tool, intent.tool)) return false
  if (rule.pattern === undefined) return true
  const subject = subjectFor(intent)
  if (rule.pattern.startsWith("regex:")) {
    try { return new RegExp(rule.pattern.slice(6), "i").test(subject) } catch { return false }
  }
  return globMatch(subject, expandHome(rule.pattern))
}

function subjectFor(intent: Intent): string {
  if (intent.tool === "bash" || intent.tool === "shell") return String(intent.args.command ?? intent.args.cmd ?? "")
  if (typeof intent.args.url === "string") return intent.args.url
  return extractPath(intent.args) ?? JSON.stringify(intent.args)
}

function extractPath(args: Readonly<Record<string, unknown>>): string | undefined {
  for (const key of ["path", "filePath", "file", "directory", "target", "cwd"]) if (typeof args[key] === "string") return args[key]
  return undefined
}

function readOnly(tool: string, risk: readonly string[]): boolean {
  return /^(?:read|glob|grep|list|lsp|git_status|git_diff|git_log)/i.test(tool) || risk.every((item) => item === "read")
}
function isEditTool(tool: string): boolean { return /^(?:write|edit|patch|apply_patch|delete|move|create)/i.test(tool) }
function mutates(tool: string, risk: readonly string[]): boolean { return isEditTool(tool) || risk.some((item) => ["write", "destructive", "network", "remote-execution"].includes(item)) }
function toolMatches(pattern: string, tool: string): boolean { return pattern === "*" || new RegExp(`^${escapeRegex(pattern).replace(/\\\*/g, ".*")}$`, "i").test(tool) }
function summarizeRisk(risk: readonly string[]): string { return risk.includes("destructive") ? "Destructive operation requires approval" : risk.includes("network") ? "External operation requires approval" : risk.includes("write") ? "Write operation requires approval" : "Operation requires approval" }

function normalizePath(path: string, cwd: string): string {
  const expanded = path.startsWith("~/") ? resolve(homedir(), path.slice(2)) : path
  return (isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded)).replace(/\\/g, "/")
}
function expandHome(pattern: string): string { return pattern.startsWith("~/") ? resolve(homedir(), pattern.slice(2)).replace(/\\/g, "/") : pattern.replace(/\\/g, "/") }
function globMatch(value: string, pattern: string): boolean {
  const source = escapeRegex(pattern).replace(/\\\*\\\*/g, ".*").replace(/\\\*/g, "[^/]*").replace(/\\\?/g, "[^/]")
  return new RegExp(`^(?:${source}|.*/${source})$`, process.platform === "win32" ? "i" : "").test(value.replace(/\\/g, "/"))
}
function escapeRegex(value: string): string { return value.replace(/[|\\{}()[\]^$+*?.-]/g, "\\$&") }
function domains(value: string): string[] {
  const result = new Set<string>()
  for (const match of value.matchAll(/\b(?:https?|wss?|ssh):\/\/([^\s/:@]+(?::[^\s/@]*)?@)?([^\s/:?#]+)/gi)) if (match[2] !== undefined) result.add(match[2].toLowerCase())
  return [...result]
}
function domainMatches(domain: string, pattern: string): boolean { return domain === pattern || (pattern.startsWith("*.") && domain.endsWith(pattern.slice(1))) }
function isRecord(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value) }
function isRule(value: unknown): value is Rule { return isRecord(value) && ["allow", "ask", "deny"].includes(String(value.effect)) && typeof value.tool === "string" }
function isMode(value: unknown): value is PermissionMode { return ["manual", "accept-edits", "plan", "dont-ask", "bypass"].includes(String(value)) }
function stringArray(value: unknown, fallback: readonly string[]): readonly string[] { return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : fallback }
function positiveInteger(value: unknown, fallback: number): number { return Number.isInteger(value) && Number(value) > 0 ? Number(value) : fallback }
function boundedNumber(value: unknown, fallback: number, minimum: number, maximum: number): number { return typeof value === "number" && Number.isFinite(value) ? Math.min(maximum, Math.max(minimum, value)) : fallback }
