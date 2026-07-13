"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { cspMode, buildCspValue, buildCspHeader } = require("../src/protection/csp");

test("CSP mode: report by default, enforce only when EDULEARN_CSP=enforce", () => {
  assert.equal(cspMode({}), "report");
  assert.equal(cspMode({ EDULEARN_CSP: "report" }), "report");
  assert.equal(cspMode({ EDULEARN_CSP: "enforce" }), "enforce");
});

test("CSP value always includes the safe hardening directives", () => {
  const value = buildCspValue(["api.exam.edu"]);
  for (const directive of [
    "default-src 'self'",
    "object-src 'none'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ]) {
    assert.match(value, new RegExp(directive.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&")));
  }
  // connect-src is widened to the allowed API host.
  assert.match(value, /connect-src 'self' api\.exam\.edu/);
});

test("CSP header name reflects report-only vs enforce", () => {
  assert.equal(
    buildCspHeader({ mode: "report" }).headerName,
    "Content-Security-Policy-Report-Only",
  );
  assert.equal(buildCspHeader({ mode: "enforce" }).headerName, "Content-Security-Policy");
});
