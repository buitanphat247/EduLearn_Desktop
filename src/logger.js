const fs = require('fs');
const path = require('path');
const { app } = require('electron');

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
    
    // Create logs/YYYY-MM-DD folder relative to user data or cwd
    const baseDir = app.isPackaged ? app.getPath('userData') : process.cwd();
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
      payload
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
  logger: globalLogger
};
