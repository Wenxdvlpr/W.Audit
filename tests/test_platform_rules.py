import unittest

from rivet.checks import scan_config


class PlatformRuleTests(unittest.TestCase):
    def test_dockerfile_risks(self):
        code = '''FROM alpine:latest
USER root
RUN curl https://example.com/install.sh | bash
ADD https://example.com/archive.tar.gz /tmp/
RUN chmod 777 /data
ENV API_KEY=Q7rM9zV3nT8pL6yK2sW4
'''
        rules = {f.rule for f in scan_config("Dockerfile", code)}
        self.assertTrue({"docker/latest", "docker/root", "docker/remote-shell", "docker/remote-add", "docker/world-writable", "docker/secret-env"} <= rules)

    def test_compose_host_exposure(self):
        code = '''services:
  database:
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - "0.0.0.0:5432:5432"
    cap_add:
      - SYS_ADMIN
'''
        rules = {f.rule for f in scan_config("compose.yaml", code)}
        self.assertTrue({"compose/privileged", "compose/host-network", "compose/docker-socket", "compose/public-database", "compose/dangerous-capability"} <= rules)

    def test_github_actions_risks(self):
        workflow = '''on: pull_request_target
permissions: write-all
jobs:
  test:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.title }}"
'''
        rules = {f.rule for f in scan_config(".github/workflows/ci.yml", workflow)}
        self.assertTrue({"ci/pull-request-target-checkout", "ci/write-all", "ci/self-hosted", "ci/event-shell-interpolation", "ci/unpinned-action"} <= rules)
        self.assertTrue(all(f.severity != "HIGH" for f in scan_config(".github/workflows/ci.yml", workflow)))

    def test_kubernetes_basics(self):
        manifest = '''apiVersion: apps/v1
kind: Deployment
spec:
  hostNetwork: true
  containers:
    - name: app
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
'''
        rules = {f.rule for f in scan_config("k8s/deployment.yaml", manifest)}
        self.assertTrue({"k8s/host-network", "k8s/privileged", "k8s/root-user", "k8s/privilege-escalation"} <= rules)


if __name__ == "__main__":
    unittest.main()
