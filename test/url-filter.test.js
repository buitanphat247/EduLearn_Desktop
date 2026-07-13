const test = require("node:test");
const assert = require("node:assert/strict");

const {
  resolveMode,
  buildAllowlist,
  hostAllowed,
  isAllowedUrl,
} = require("../src/protection/url-filter");

test("resolveMode: exam-shell enforces by default, lobby reports (H1)", () => {
  assert.equal(resolveMode({ EDULEARN_EXAM_SHELL: "1" }), "enforce");
  assert.equal(resolveMode({}), "report");
  // explicit overrides win in both directions
  assert.equal(
    resolveMode({ EDULEARN_EXAM_SHELL: "1", EDULEARN_URL_FILTER: "report" }),
    "report",
  );
  assert.equal(resolveMode({ EDULEARN_URL_FILTER: "enforce" }), "enforce");
});

test("buildAllowlist covers the start host and localhost only when local", () => {
  const local = buildAllowlist({ startUrl: "http://localhost:3000" });
  assert.ok(local.has("localhost"));
  assert.ok(local.has("127.0.0.1"));

  const prod = buildAllowlist({
    startUrl: "https://exam.edu/room/1",
    extraHosts: ["api.edu"],
  });
  assert.ok(prod.has("exam.edu"));
  assert.ok(prod.has("api.edu"));
  assert.ok(!prod.has("localhost"));
});

test("hostAllowed matches exact hosts and subdomains", () => {
  const allow = buildAllowlist({ startUrl: "https://exam.edu" });
  assert.equal(hostAllowed("exam.edu", allow), true);
  assert.equal(hostAllowed("cdn.exam.edu", allow), true); // subdomain of allowed
  assert.equal(hostAllowed("evil.com", allow), false);
  assert.equal(hostAllowed("notexam.edu", allow), false); // not a subdomain
});

test("isAllowedUrl: internal schemes ok, off-allowlist network + file denied", () => {
  const allow = buildAllowlist({ startUrl: "https://exam.edu", extraHosts: ["api.edu"] });
  assert.equal(isAllowedUrl("https://exam.edu/room", allow), true);
  assert.equal(isAllowedUrl("https://api.edu/attempts", allow), true);
  assert.equal(isAllowedUrl("data:text/html,x", allow), true);
  assert.equal(isAllowedUrl("blob:https://exam.edu/abc", allow), true);
  assert.equal(isAllowedUrl("https://cheatsite.com/answers", allow), false);
  assert.equal(isAllowedUrl("file:///C:/Windows/System32/cmd.exe", allow), false);
  assert.equal(isAllowedUrl("ftp://exam.edu/x", allow), false);
  assert.equal(isAllowedUrl("not a url", allow), false);
});
