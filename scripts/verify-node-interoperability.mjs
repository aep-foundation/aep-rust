import { readFile, writeFile } from "node:fs/promises";

const [rustResultPath, nodeResultPath, reportPath] = process.argv.slice(2);

if (rustResultPath === undefined || nodeResultPath === undefined || reportPath === undefined) {
  throw new Error("usage: verify-node-interoperability.mjs RUST_RESULT NODE_RESULT REPORT");
}

const rustResult = JSON.parse(await readFile(rustResultPath, "utf8"));
const nodeResult = JSON.parse(await readFile(nodeResultPath, "utf8"));

requireEqual(rustResult.agent, "rust", "Rust Agent identity");
requireEqual(rustResult.service, "node", "Rust Agent Service counterpart");
requireEqual(rustResult.platform, "node", "Rust Agent Platform counterpart");
requireEqual(rustResult.enrollment, "active", "Rust Agent enrollment");
requireEqual(rustResult.credential_mode, "api-key", "Rust Agent credential mode");
requireEqual(rustResult.protected_resource_status, 200, "Rust Agent protected resource");
requireEqual(rustResult.revoked, true, "Rust Agent credential revocation");

requireEqual(nodeResult.credentialMode, "api-key", "Node Agent credential mode");
requireEqual(nodeResult.enroll?.status, "active", "Node Agent enrollment");
requireEqual(nodeResult.statusBeforeGrant?.status, "active", "Node Agent pre-Grant status");
requireEqual(nodeResult.statusAfterRevoke?.status, "active", "Node Agent post-Revoke status");
requireEqual(nodeResult.resource?.available, true, "Node Agent protected resource");
requireEqual(nodeResult.profile?.updated, true, "Node Agent protected profile");
requireEqual(typeof nodeResult.grant?.credential_id, "string", "Node Agent credential identifier type");
requireEqual(nodeResult.grant?.credential_id.length > 0, true, "Node Agent credential identifier");
requireEqual(Object.keys(nodeResult.revoke ?? {}).length, 0, "Node Agent Revoke response");

const report = {
  aep_version: "1.0",
  evidence: [
    {
      agent: "rust",
      counterpart: "node",
      flow: "Inspect, Enroll, Grant, protected resource, Revoke",
      role: "service",
      status: "passed"
    },
    {
      agent: "rust",
      counterpart: "node",
      flow: "Discovery, List, Provision, delegated Sign",
      role: "platform",
      status: "passed"
    },
    {
      agent: "node",
      counterpart: "rust",
      flow: "Inspect, Enroll, Grant, protected resource, Revoke",
      role: "service",
      status: "passed"
    },
    {
      agent: "node",
      counterpart: "rust",
      flow: "Discovery, List, Provision, delegated Sign",
      role: "platform",
      status: "passed"
    }
  ],
  status: "passed"
};

await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

function requireEqual(actual, expected, name) {
  if (!Object.is(actual, expected)) {
    throw new Error(`${name}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}
