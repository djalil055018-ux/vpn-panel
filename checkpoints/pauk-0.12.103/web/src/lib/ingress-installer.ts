import { installationOrigin } from "./installation-origin";

export function ingressCompanionInstallCommand(origin: string | null) {
  const configured = installationOrigin(origin ?? undefined);
  if (!configured) return "";
  return `curl -fsSL ${configured}/install/install-ingress-agent-v0.1.4.py -o /root/pauk-ingress-install.py && echo 'b7aa7628e09f96cf3b8c1c0df0161144d623a0d0797559354f53627d5b06b719  /root/pauk-ingress-install.py' | sha256sum -c - && python3 /root/pauk-ingress-install.py --panel-origin ${configured} && systemctl is-active pauk-ingress-agent.service`;
}
