import unittest

from agent_jail.backend import choose_backend


class BackendTests(unittest.TestCase):
    def test_linux_prefers_bwrap_when_available(self):
        backend = choose_backend(
            "linux",
            have=lambda name: name == "bwrap",
        )
        self.assertEqual(backend["name"], "bubblewrap")

    def test_linux_falls_back_to_proot(self):
        backend = choose_backend(
            "linux",
            have=lambda name: name == "proot",
        )
        self.assertEqual(backend["name"], "proot")

    def test_macos_uses_host_mode(self):
        backend = choose_backend("darwin", have=lambda name: False)
        self.assertEqual(backend["name"], "host")

    def test_macos_prefers_alcless_when_available(self):
        backend = choose_backend("darwin", have=lambda name: name == "alcless")
        self.assertEqual(backend["name"], "alcless")
