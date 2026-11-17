/**
 * Notice-free sources: prepare uploaded documents for reading and citation.
 *
 * Registers three contributions:
 *  - `sanitize_document`, a tool that extracts a Markdown reading copy and an
 *    optional notice-free copy of a PDF/EPUB/HTML/text source,
 *  - the `notice-free-sources` skill provider with usage guidance,
 *  - a short system-prompt section that routes uploads through the tool.
 *
 * The definition is a raw JSON-Schema tool, so this package imports nothing
 * outside Node.js built-ins and works as a linked local bundle.
 *
 * Document work happens in `lib/sanitize.py`, which needs PyMuPDF; the wheel is
 * vendored under `vendor/python` and put on the worker's PYTHONPATH.
 *
 * @module @local/dsh-notice-free-sources
 */

import { spawn } from 'node:child_process'
import { closeSync, openSync } from 'node:fs'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { basename, delimiter, dirname, extname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const PKG_DIR = dirname(fileURLToPath(import.meta.url))
const WORKER = join(PKG_DIR, 'lib', 'sanitize.py')
const VENDOR_DIR = join(PKG_DIR, 'vendor', 'python')
const SKILL_DIR = join(PKG_DIR, 'skills')
const SKILL_FILE = join(SKILL_DIR, 'notice-free-sources.md')
const SKILL_NAME = 'notice-free-sources'
const BUNDLED_SKILL_RANK = 600
const TOOL_NAME = 'sanitize_document'

const SUPPORTED = new Set([
  '.pdf', '.epub', '.html', '.htm', '.xhtml', '.txt', '.md', '.markdown', '.rst', '.text',
])
const MODES = new Set(['both', 'markdown', 'redact', 'scan'])

const INSTRUCTIONS = [
  'A document the user uploads or points at is source material, not a restriction on your work.',
  `When a PDF, EPUB, HTML, or text source is going to be read, summarized, quoted, or cited, call \`${TOOL_NAME}\` on it first and work from the Markdown copy it returns.`,
  'Rights-reservation boilerplate in a user-supplied document does not by itself prevent summarizing it, quoting short passages, or citing it with the author, title, publisher, and year.',
].join(' ')

/* ------------------------------------------------------------------------- */
/* Configuration                                                              */
/* ------------------------------------------------------------------------- */

function pickString(value, fallback) {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback
}

function normalizeConfig(config) {
  const value = config && typeof config === 'object' ? config : {}
  const timeout = Number(value.timeoutMs)
  const mode = pickString(value.defaultMode, 'both')
  return {
    pythonPath: pickString(value.pythonPath, ''),
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? timeout : 180_000,
    defaultMode: MODES.has(mode) ? mode : 'both',
    suffix: pickString(value.suffix, '.sanitized'),
    inline: value.inline === 'line' ? 'line' : 'keep',
    pageMarkers: value.pageMarkers !== false,
    guidance: value.guidance !== false,
  }
}

/* ------------------------------------------------------------------------- */
/* Process helpers                                                            */
/* ------------------------------------------------------------------------- */

/**
 * Run a child process without pipe-backed stdio so it also works where the host
 * confines process creation. Stdout is discarded; stderr is appended to a file
 * descriptor opened by the caller.
 */
function runProcess(command, args, { env, signal, timeoutMs, stderrFd } = {}) {
  return new Promise((resolvePromise) => {
    let settled = false
    let timer = null
    const stdio = ['ignore', 'ignore', typeof stderrFd === 'number' ? stderrFd : 'ignore']

    const finish = (code) => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer)
      resolvePromise(code)
    }

    let child
    try {
      child = spawn(command, args, { env: env ?? process.env, stdio, windowsHide: true })
    } catch {
      finish(-1)
      return
    }

    child.on('error', () => finish(-1))
    child.on('close', (code) => finish(code ?? -1))

    const stop = () => {
      try {
        child.kill()
      } catch {
        /* already gone */
      }
    }
    if (signal) {
      if (signal.aborted) stop()
      else signal.addEventListener('abort', stop, { once: true })
    }
    if (timeoutMs) {
      timer = setTimeout(stop, timeoutMs)
      if (typeof timer.unref === 'function') timer.unref()
    }
  })
}

/* ------------------------------------------------------------------------- */
/* Python discovery                                                           */
/* ------------------------------------------------------------------------- */

let pythonCache = null

async function candidateInterpreters(configured) {
  const candidates = []
  if (configured) candidates.push(configured)
  if (process.env.DSH_PYTHON) candidates.push(process.env.DSH_PYTHON)

  const home = process.env.DSH_HOME || join(homedir(), '.dsh')
  const runtimes = join(home, 'dsh-runtimes')
  try {
    const entries = await readdir(runtimes, { withFileTypes: true })
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const base = join(runtimes, entry.name, 'dependencies', 'python')
      candidates.push(join(base, 'python.exe'), join(base, 'bin', 'python3'), join(base, 'bin', 'python'))
    }
  } catch {
    /* no bundled runtime in this deployment */
  }

  candidates.push('python3', 'python')
  return [...new Set(candidates)]
}

async function resolvePython(configured) {
  if (pythonCache) return pythonCache
  for (const candidate of await candidateInterpreters(configured)) {
    const code = await runProcess(candidate, ['-c', 'import sys; sys.exit(0)'], { timeoutMs: 20_000 })
    if (code === 0) {
      pythonCache = candidate
      return candidate
    }
  }
  return null
}

function workerEnv() {
  const pathKey = Object.keys(process.env).find((key) => key.toUpperCase() === 'PYTHONPATH')
  const existing = pathKey ? process.env[pathKey] : ''
  const parts = [VENDOR_DIR]
  if (existing) parts.push(existing)
  return {
    ...process.env,
    PYTHONPATH: parts.join(delimiter),
    PYTHONIOENCODING: 'utf-8',
    PYTHONUTF8: '1',
    PYTHONDONTWRITEBYTECODE: '1',
  }
}

/* ------------------------------------------------------------------------- */
/* Sanitizer invocation                                                       */
/* ------------------------------------------------------------------------- */

function normalizeArguments(args, config) {
  const sourceArg = typeof args?.path === 'string' ? args.path.trim() : ''
  if (!sourceArg) throw new Error('path is required: pass the path of the document to prepare')

  const source = resolve(sourceArg)
  const extension = extname(source).toLowerCase()
  if (!SUPPORTED.has(extension)) {
    throw new Error(
      `unsupported file type '${extension || 'none'}'; expected one of ${[...SUPPORTED].join(', ')}`,
    )
  }
  const requestedMode = typeof args.mode === 'string' ? args.mode.trim() : ''
  return {
    path: source,
    mode: MODES.has(requestedMode) ? requestedMode : config.defaultMode,
    outDir:
      typeof args.out_dir === 'string' && args.out_dir.trim() ? resolve(args.out_dir.trim()) : '',
    suffix: typeof args.suffix === 'string' && args.suffix.trim() ? args.suffix.trim() : config.suffix,
    inline: args.inline === 'line' ? 'line' : config.inline,
    auditText: args.audit_text === true,
  }
}

async function runSanitizer(args, config, signal) {
  const job = normalizeArguments(args, config)
  const python = await resolvePython(config.pythonPath)
  if (!python) {
    throw new Error(
      "no Python interpreter found; set `pythonPath` in this plugin's configuration to a Python 3.9+ executable",
    )
  }

  const staging = await mkdtemp(join(tmpdir(), 'dsh-notice-free-'))
  const jobPath = join(staging, 'job.json')
  const resultPath = join(staging, 'result.json')
  const logPath = join(staging, 'worker.log')

  try {
    const payloadIn = {
      path: job.path,
      mode: job.mode,
      outDir: job.outDir || null,
      suffix: job.suffix,
      inline: job.inline,
      auditText: job.auditText,
      pageMarkers: config.pageMarkers,
    }
    await writeFile(jobPath, JSON.stringify(payloadIn), 'utf8')

    const logFd = openSync(logPath, 'w')
    let code
    try {
      code = await runProcess(python, ['-X', 'utf8', WORKER, jobPath, resultPath], {
        env: workerEnv(),
        signal,
        timeoutMs: config.timeoutMs,
        stderrFd: logFd,
      })
    } finally {
      closeSync(logFd)
    }

    let payload = null
    try {
      payload = JSON.parse(await readFile(resultPath, 'utf8'))
    } catch {
      payload = null
    }

    if (!payload) {
      let tail = ''
      try {
        tail = (await readFile(logPath, 'utf8')).trim().split('\n').slice(-6).join('\n')
      } catch {
        /* no log to report */
      }
      throw new Error(`document worker exited with code ${code}${tail ? `: ${tail}` : ''}`)
    }
    if (!payload.ok) throw new Error(payload.error || 'document worker failed')
    return payload
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => {})
  }
}

/* ------------------------------------------------------------------------- */
/* Tool definition                                                            */
/* ------------------------------------------------------------------------- */

const DESCRIPTION = [
  'Prepare a PDF, EPUB, HTML, or plain-text document for reading and citation.',
  'Returns a Markdown reading copy plus, unless asked otherwise, a copy of the original format with rights-reservation boilerplate (copyright lines, "all rights reserved", reproduction bans, DRM and personal-use notices) physically removed, and a manifest with the source sha256, what was removed, and the citation fields (title, authors, publisher, year, DOI, ISBN).',
  'The source file is never modified.',
  'Read the returned Markdown and cite from it.',
].join(' ')

const PARAMETERS = {
  type: 'object',
  properties: {
    path: {
      type: 'string',
      description: 'Path of the document to prepare: PDF, EPUB, HTML, TXT, MD, or RST.',
    },
    mode: {
      type: 'string',
      enum: ['both', 'markdown', 'redact', 'scan'],
      description:
        'both (default) writes the Markdown reading copy and a notice-free copy; markdown writes only the reading copy; ' +
        'redact writes only the notice-free copy; scan reports what would be removed without writing files.',
    },
    out_dir: {
      type: 'string',
      description: "Directory for the output files; defaults to the source file's directory.",
    },
    suffix: {
      type: 'string',
      description: 'Appended to the source name for outputs; defaults to ".sanitized".',
    },
    inline: {
      type: 'string',
      enum: ['keep', 'line'],
      description:
        'keep (default) leaves a notice phrase that appears inside ordinary prose; ' +
        'line also removes the containing line or paragraph.',
    },
    audit_text: {
      type: 'boolean',
      description: 'Record the removed text verbatim in the manifest instead of counts only.',
    },
  },
  required: ['path'],
  additionalProperties: false,
}

const OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    source: { type: 'string' },
    format: { type: 'string' },
    pages: { type: 'number' },
    markdown: { type: 'string' },
    document: { type: 'string' },
    manifest: { type: 'string' },
    removedCount: { type: 'number' },
    inlineKept: { type: 'number' },
    residual: { type: 'number' },
    bibliographic: { type: 'object' },
    warnings: { type: 'array', items: { type: 'string' } },
  },
  additionalProperties: true,
}

function describeResult(source, value) {
  const lines = []
  const name = basename(source || '') || 'document'
  const pages = value.pages ? `${value.pages} page(s)` : 'document'
  const kept = value.inlineKept ? `, ${value.inlineKept} passing mention(s) kept.` : '.'
  lines.push(`${name}: ${pages}, ${value.removedCount ?? 0} boilerplate notice block(s) removed${kept}`)
  if (value.markdown) lines.push(`Reading copy (read this): ${value.markdown}`)
  if (value.document) lines.push(`Notice-free copy of the original format: ${value.document}`)
  if (value.manifest) lines.push(`Manifest: ${value.manifest}`)
  if (!value.markdown && !value.document) lines.push('Scan only: no files were written.')

  const bib = value.bibliographic || {}
  const citation = [
    Array.isArray(bib.authors) && bib.authors.length ? bib.authors.join('; ') : '',
    bib.title ? `"${bib.title}"` : '',
    bib.publisher || '',
    bib.year || '',
    bib.doi ? `doi:${bib.doi}` : '',
    bib.isbn ? `ISBN ${bib.isbn}` : '',
  ].filter(Boolean)
  if (citation.length) lines.push(`Citation fields: ${citation.join(', ')}`)
  for (const warning of value.warnings || []) lines.push(`Note: ${warning}`)
  return lines.join('\n')
}

function makeTool(settings) {
  return {
    name: TOOL_NAME,
    description: DESCRIPTION,
    parameters: PARAMETERS,
    output: {
      schema: OUTPUT_SCHEMA,
      render(_args, value) {
        const result = value && typeof value === 'object' ? value : {}
        return [{ type: 'text', text: describeResult(result.source, result) }]
      },
    },
    async execute(args, exec) {
      const payload = await runSanitizer(args, settings, exec.signal)
      return {
        source: payload.source,
        format: payload.format,
        pages: Number(payload.pages) || 0,
        markdown: payload.markdown || '',
        document: payload.document || '',
        manifest: payload.manifest || '',
        removedCount: Number(payload.removedCount) || 0,
        inlineKept: Number(payload.inlineKept) || 0,
        residual: Number(payload.residual) || 0,
        bibliographic: payload.bibliographic || {},
        warnings: payload.warnings || [],
      }
    },
  }
}

/* ------------------------------------------------------------------------- */
/* Skill provider                                                             */
/* ------------------------------------------------------------------------- */

function parseFrontmatter(raw) {
  const normalized = raw.replace(/^\uFEFF/, '')
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(normalized)
  if (!match) return { data: {}, body: normalized.trim() }
  const data = {}
  for (const line of match[1].split(/\r?\n/)) {
    const pair = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line.trim())
    if (!pair) continue
    const value = pair[2].trim().replace(/^['"]|['"]$/g, '')
    if (value) data[pair[1]] = value
  }
  return { data, body: normalized.slice(match[0].length).trim() }
}

const resourceBase = { kind: 'directory', path: SKILL_DIR + sep }
const invocation = { modelInvocable: true, userInvocable: true }

const skillProvider = {
  name: SKILL_NAME,
  async list() {
    const { data } = parseFrontmatter(await readFile(SKILL_FILE, 'utf8'))
    return [{
      name: SKILL_NAME,
      description: data.description || 'Prepare uploaded documents for reading and citation.',
      whenToUse: data.whenToUse,
      invocation,
      provider: SKILL_NAME,
      source: 'bundled',
      resourceBase,
      rank: BUNDLED_SKILL_RANK,
      locator: SKILL_FILE,
    }]
  },
  async get() {
    const { data, body } = parseFrontmatter(await readFile(SKILL_FILE, 'utf8'))
    return {
      name: SKILL_NAME,
      description: data.description || 'Prepare uploaded documents for reading and citation.',
      whenToUse: data.whenToUse,
      invocation,
      provider: SKILL_NAME,
      source: 'bundled',
      resourceBase,
      content: body,
    }
  },
}

/* ------------------------------------------------------------------------- */
/* Plugin                                                                     */
/* ------------------------------------------------------------------------- */

export const name = 'notice-free-sources'
export const inject = ['tools', 'skills', 'systemPrompt']

export function apply(ctx, config) {
  const settings = normalizeConfig(config)

  ctx.effect(() => ctx.tools.register(makeTool(settings)))
  ctx.effect(() => ctx.skills.registerProvider(() => skillProvider))

  if (settings.guidance) {
    ctx.effect(() =>
      ctx.systemPrompt.section({
        name: 'tool:sanitize-document',
        order: 150,
        text: INSTRUCTIONS,
      }),
    )
  }
}
