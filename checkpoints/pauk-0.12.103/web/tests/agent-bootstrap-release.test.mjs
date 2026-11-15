import assert from "node:assert/strict";
import test from "node:test";
import { registerHooks } from "node:module";
import { amneziaWGInstallerRelease, nativeAgentBootstrapRelease } from "../src/lib/agent-bootstrap-release.ts";

const prefix = new URL("../src/lib/", import.meta.url).href;
const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
  if (specifier.startsWith("./") && context.parentURL?.startsWith(prefix) && !specifier.endsWith(".ts"))
    return nextResolve(new URL(specifier + ".ts", context.parentURL).href, context);
  return nextResolve(specifier, context);
} });
const { nodeInstallCommand } = await import("../src/lib/node-runtime.ts");
hooks.deregister();

const node = "00000000-0000-4000-8000-000000000001";
test("all new protocol nodes use the pinned installer that installs private backups", () => {
  for (const runtime of ["xray", "hysteria2", "wireguard", "amneziawg", "openvpn", "pptp"]) {
    const installer = runtime === "amneziawg" ? amneziaWGInstallerRelease : nativeAgentBootstrapRelease;
    const command = nodeInstallCommand(runtime, node, "https://panel.example:8443");
    assert.ok(command.includes(`/install/${installer.installerFilename}`));
    assert.ok(command.includes(`/artifacts/node-agent/${nativeAgentBootstrapRelease.version}/linux-amd64/vpn-node-agent`));
    assert.ok(command.includes(installer.installerSHA256 + "  /root/vpn-node-tool.py"));
    assert.ok(command.includes(nativeAgentBootstrapRelease.binarySHA256 + "  /root/vpn-node-agent.download"));
    assert.ok(command.includes(`--require-bootstrap --expected-node-id ${node} --core ${runtime}`));
    if (runtime === "amneziawg") {
      assert.notEqual(installer.installerFilename, nativeAgentBootstrapRelease.installerFilename);
      assert.ok(command.includes("--runtime-artifact-file /root/pauk-amneziawg.tar.gz"));
    }
    assert.ok(!command.includes("install-ingress-agent"));
    assert.ok(!command.includes("winphonestore.name"));
    assert.ok(!command.includes("v0.2.50.py"));
  }
});
test("new installation commands remain bound to a valid origin and node identity", () => {
  for (const id of ["", "owner; command", node + " --repair"]) assert.throws(() => nodeInstallCommand("xray", id, "https://panel.example"));
  for (const origin of ["http://panel.example", "https://user:password@panel.example", "https://panel.example/other", "https://panel.example?next=other"])
    assert.throws(() => nodeInstallCommand("xray", node, origin));
});
