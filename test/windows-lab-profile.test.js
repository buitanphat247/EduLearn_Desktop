const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const profile = JSON.parse(
  fs.readFileSync(
    path.join(
      __dirname,
      "..",
      "deployment",
      "windows-lab",
      "managed-lab-profile.json",
    ),
    "utf8",
  ),
);

test("managed lab profile is fail-safe and cannot silently enable enforcement", () => {
  assert.equal(profile.schemaVersion, 1);
  assert.equal(profile.managedDevicesOnly, true);
  assert.equal(profile.deploymentMode, "audit");
  assert.equal(profile.appLocker.enforcementMode, "AuditOnly");
  assert.equal(profile.wdac.policyMode, "Audit");
  assert.equal(profile.assignedAccess.enabled, false);
  assert.equal(profile.rollout.pilotRingRequired, true);
  assert.equal(profile.rollout.recoveryAccountRequired, true);
  assert.equal(profile.rollout.restorePointRequired, true);
  assert.equal(profile.rollout.auditDays >= 7, true);
});
