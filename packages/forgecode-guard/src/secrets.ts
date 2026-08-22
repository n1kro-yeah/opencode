import { createHash } from "node:crypto"

export interface Finding {
  readonly kind: string
  readonly value: string
  readonly start: number
  readonly end: number
  readonly line: number
  readonly confidence: "low" | "medium" | "high"
  readonly fingerprint: string
}

interface Pattern {
  readonly kind: string
  readonly regex: RegExp
  readonly confidence: Finding["confidence"]
  readonly group?: number
}

const PATTERNS: readonly Pattern[] = [
  { kind: "aws-access-key", regex: /\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b/g, confidence: "high" },
  { kind: "github-token", regex: /\b(?:gh[opurs]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{70,255})\b/g, confidence: "high" },
  { kind: "gitlab-token", regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, confidence: "high" },
  { kind: "openai-key", regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g, confidence: "high" },
  { kind: "anthropic-key", regex: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g, confidence: "high" },
  { kind: "google-api-key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, confidence: "high" },
  { kind: "slack-token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, confidence: "high" },
  { kind: "stripe-key", regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g, confidence: "high" },
  { kind: "jwt", regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, confidence: "medium" },
  { kind: "private-key", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, confidence: "high" },
  { kind: "basic-auth-url", regex: /\b[a-z][\w+.-]*:\/\/([^\s/:@]+):([^\s/@]+)@[^\s]+/gi, confidence: "high" },
  { kind: "database-url", regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s]+/gi, confidence: "medium" },
  { kind: "generic-secret", regex: /\b(?:api[_-]?key|secret|token|password|passwd|credential)\s*[:=]\s*["']?([A-Za-z0-9_+\/=.-]{16,})["']?/gi, confidence: "medium", group: 1 },
]

export function scanSecrets(content: string, limit = 100): Finding[] {
  const findings: Finding[] = []
  const seen = new Set<string>()
  for (const pattern of PATTERNS) {
    pattern.regex.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = pattern.regex.exec(content)) !== null && findings.length < limit) {
      const value = match[pattern.group ?? 0] ?? match[0]
      const start = match.index + Math.max(0, match[0].indexOf(value))
      const fingerprint = digest(value)
      if (!seen.has(fingerprint) && !placeholder(value)) {
        seen.add(fingerprint)
        findings.push({ kind: pattern.kind, value, start, end: start + value.length, line: lineAt(content, start), confidence: pattern.confidence, fingerprint })
      }
      if (match[0].length === 0) pattern.regex.lastIndex += 1
    }
  }
  const highEntropy = /\b[A-Za-z0-9_+\/=.-]{24,128}\b/g
  let match: RegExpExecArray | null
  while ((match = highEntropy.exec(content)) !== null && findings.length < limit) {
    const value = match[0]
    const fingerprint = digest(value)
    const entropy = shannonEntropy(value)
    if (entropy > 4.55 && /[A-Za-z]/.test(value) && /\d/.test(value) && !seen.has(fingerprint) && !placeholder(value)) {
      seen.add(fingerprint)
      findings.push({ kind: "high-entropy", value, start: match.index, end: match.index + value.length, line: lineAt(content, match.index), confidence: entropy > 4.9 ? "medium" : "low", fingerprint })
    }
  }
  return findings.sort((left, right) => left.start - right.start)
}

export function redactSecrets(content: string, findings = scanSecrets(content)): string {
  let output = content
  for (const finding of [...findings].sort((left, right) => right.start - left.start)) output = output.slice(0, finding.start) + redaction(finding.value) + output.slice(finding.end)
  return output
}

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0
  const counts = new Map<string, number>()
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1)
  let result = 0
  for (const count of counts.values()) { const p = count / value.length; result -= p * Math.log2(p) }
  return result
}

function redaction(value: string): string { return value.length < 9 ? "[REDACTED]" : `${value.slice(0, 3)}…${value.slice(-3)}[REDACTED]` }
function digest(value: string): string { return createHash("sha256").update(value).digest("hex").slice(0, 16) }
function placeholder(value: string): boolean { return /^(?:x+|0+|1+|a+|test|example|placeholder|changeme|your[_-])/i.test(value) || value.includes("${") || value.includes("example.com") }
function lineAt(content: string, offset: number): number { let line = 1; for (let index = 0; index < offset; index += 1) if (content.charCodeAt(index) === 10) line += 1; return line }
