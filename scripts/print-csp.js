"use strict";

// Dev helper (VS-03): print the EXACT CSP header the exam window emits in DEV
// vs PACKAGED, without building anything. Use it to eyeball that the packaged
// policy enforces and carries NO 'unsafe-eval'.
//
// Usage:
//   node scripts/print-csp.js [connectHost ...]
//   node scripts/print-csp.js api.edulearn.vn wss://api.edulearn.vn

const { buildCspHeader } = require("../src/protection/csp");

const hosts = process.argv.slice(2);

for (const packaged of [false, true]) {
  // Dev = report-only (dry-run); a PACKAGED exam-shell always enforces.
  const mode = packaged ? "enforce" : "report";
  const h = buildCspHeader({ connectHosts: hosts, mode, packaged });
  console.log(`\n=== ${packaged ? "PACKAGED exam-shell (production)" : "DEV / lobby"} ===`);
  console.log(`${h.headerName}: ${h.value}`);
  console.log(`  unsafe-eval present : ${h.value.includes("'unsafe-eval'")}`);
  console.log(`  unsafe-inline (script): ${/script-src[^;]*'unsafe-inline'/.test(h.value)}`);
}
console.log("");
