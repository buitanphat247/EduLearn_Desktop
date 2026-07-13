const fs = require('fs');
const path = require('path');
const { app } = require('electron');

// L2: redact secrets before they hit the JSONL sink. The Rust core already
// redacts; the Electron logger did not, so auth tokens (cookies `_at`/`_rt`/
// `_csrf`), the IPC secret, capability tokens, passwords and clipboard contents
// could leak into on-disk logs. Keys are matched case-insensitively.
const REDACTED = '[REDACTED]';
const SENSITIVE_EXACT_KEYS = new Set(['_at', '_rt', '_u', '_csrf']);
const SENSITIVE_KEY_PATTERNS = [
  'password',
  'passwd',
  'secret',
  'token',
  'cookie',
  'authorization',
  'credential',
  'clipboard',
  'apikey',
  'api_key',
  'bearer',
];

function isSensitiveKey(key) {
  if (typeof key !== 'string') return false;
  const lower = key.toLowerCase();
  if (SENSITIVE_EXACT_KEYS.has(lower)) return true;
  return SENSITIVE_KEY_PATTERNS.some((pattern) => lower.includes(pattern));
}

// Deep-clone `value` with any sensitive-keyed field replaced by [REDACTED].
// Depth- and cycle-guarded so a pathological payload can never hang the logger.
function redactSensitive(value, depth = 0, seen = new WeakSet()) {
  if (depth > 8 || value === null || typeof value !== 'object') {
    return value;
  }
  if (seen.has(value)) {
    return '[Circular]';
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redactSensitive(item, depth + 1, seen));
  }

  const out = {};
  for (const [key, val] of Object.entries(value)) {
    out[key] = isSensitiveKey(key)
      ? REDACTED
      : redactSensitive(val, depth + 1, seen);
  }
  return out;
}

function resolveLoggerBaseDir(appLike = app) {
  try {
    if (appLike && !appLike.isDestroyed?.()) {
      return appLike.getPath("userData");
    }
  } catch {}

  return path.resolve(__dirname, "..");
}

class Logger {
  constructor() {
    this.streams = {};
    this.logDir = null;
    this.sessionId = null;
    this.processState = null;
    this.isInitialized = false;
  }

  bootstrap() {
    if (this.isInitialized) return;

    const date = new Date();
    const dateString = date.toISOString().split('T')[0]; // YYYY-MM-DD
    
    // Keep logs out of the current working directory because Windows can
    // launch Electron from system32, which is not writable for our process.
    const baseDir = resolveLoggerBaseDir();
    this.logDir = path.join(baseDir, 'logs', dateString);

    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }

    // Initialize writers with { flags: 'a' } for append
    const categories = ['application', 'session', 'protection', 'error', 'audit'];
    categories.forEach(category => {
      this.streams[category] = fs.createWriteStream(
        path.join(this.logDir, `${category}.jsonl`),
        { flags: 'a' }
      );
    });

    this.attachToTerminal();
    this.isInitialized = true;
    
    this.info('application', 'logger_initialized', { logDir: this.logDir });
  }

  attachToTerminal() {
    const originalConsoleLog = console.log;
    const originalConsoleError = console.error;
    const originalConsoleWarn = console.warn;
    const originalConsoleDebug = console.debug || console.log;

    console.log = (...args) => {
      originalConsoleLog(...args);
      this._writeLog('info', 'application', 'console_log', { message: args.join(' ') });
    };

    console.error = (...args) => {
      originalConsoleError(...args);
      this._writeLog('error', 'error', 'console_error', { message: args.join(' ') });
    };

    console.warn = (...args) => {
      originalConsoleWarn(...args);
      this._writeLog('warn', 'application', 'console_warn', { message: args.join(' ') });
    };

    console.debug = (...args) => {
      originalConsoleDebug(...args);
      this._writeLog('debug', 'application', 'console_debug', { message: args.join(' ') });
    };
  }

  setSessionContext(sessionId, processState) {
    if (sessionId !== undefined) this.sessionId = sessionId;
    if (processState !== undefined) this.processState = processState;
  }

  _writeLog(level, category, event, payload = {}) {
    if (!this.isInitialized) return;

    const stream = this.streams[category] || this.streams['application'];
    if (!stream) return;

    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      module: category,
      event,
      sessionId: this.sessionId || 'N/A',
      processState: this.processState || 'N/A',
      payload: redactSensitive(payload)
    };

    const jsonl = JSON.stringify(logEntry) + '\n';
    stream.write(jsonl);
    
    // Optionally buffer and flush if we want in-memory buffer logic, 
    // but createWriteStream does decent buffering natively.
  }

  info(category, event, payload) {
    this._writeLog('info', category, event, payload);
  }

  error(category, event, payload) {
    this._writeLog('error', category, event, payload);
  }

  warn(category, event, payload) {
    this._writeLog('warn', category, event, payload);
  }

  debug(category, event, payload) {
    this._writeLog('debug', category, event, payload);
  }

  logProtectionFailure(event, payload, sessionState, prohibitedProcesses, lastScans, requestId, rustResponse) {
    this.error('error', event, {
      ...payload,
      sessionState,
      prohibitedProcesses,
      lastScans,
      requestId,
      rustResponse,
      failureType: 'PROTECTION_FAILURE'
    });
  }
}

const globalLogger = new Logger();

module.exports = {
  logger: globalLogger,
  resolveLoggerBaseDir,
  redactSensitive,
  isSensitiveKey,
};
