import unittest

from agent_jail.proxy import ProxyPolicy


class ProxyTests(unittest.TestCase):
    def test_proxy_denies_unknown_host_when_default_is_deny(self):
        policy = ProxyPolicy(
            [
                {"kind": "network", "host": "api.openai.com", "allow": True},
            ],
            default_allow=False,
        )
        verdict = policy.decide("CONNECT", "example.com", 443)
        self.assertEqual(verdict["decision"], "deny")

    def test_proxy_allows_matching_host(self):
        policy = ProxyPolicy(
            [
                {"kind": "network", "host": "api.openai.com", "allow": True},
            ],
            default_allow=False,
        )
        verdict = policy.decide("CONNECT", "api.openai.com", 443)
        self.assertEqual(verdict["decision"], "allow")
