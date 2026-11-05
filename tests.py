from types import SimpleNamespace
from unittest.mock import patch, MagicMock
import socket
import ssl
import dns.resolver
import dns.exception
import pandas as pd
from django.test import TestCase, SimpleTestCase, Client, override_settings
from .features import normalize_url, extract_url_features, FEATURE_NAMES, domain_group
from .services import dns_analysis, check_tls, is_public_address, assess_risk, ScanError
from .models import WebsiteScan
from .reputation import check_reputation
from ml.training.train_model import prepare_data

class FeatureTests(SimpleTestCase):
    def test_normalization_and_feature_order(self):
        url = normalize_url("www.hackerrank.com")
        self.assertEqual(url, "https://www.hackerrank.com/")
        features = extract_url_features(url)
        self.assertEqual(list(features), FEATURE_NAMES)
        self.assertEqual(len(features), 11)
        self.assertEqual(features["uses_https"], 1)
    def test_reject_invalid_and_nonstandard_ports(self):
        for url in ["file:///etc/passwd", "https://user:secret@example.com", "https://example.com:8080", "https://example.com:80", "https://exa mple.com", "https://example.com/\nhello"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                normalize_url(url)
    def test_ipv6_and_unicode(self):
        self.assertEqual(normalize_url("::1"), "https://[::1]/")
        self.assertEqual(extract_url_features(normalize_url("8.8.8.8"))["ip_host"], 1)
        self.assertEqual(normalize_url("https://example.com:443/a#fragment"), "https://example.com/a")
    def test_registered_domain_groups(self):
        self.assertEqual(domain_group("https://a.example.co.uk/a"), domain_group("https://b.example.co.uk/b"))
        self.assertNotEqual(domain_group("https://alice.github.io/"), domain_group("https://bob.github.io/"))
    def test_uci_labels_duplicates_and_conflicts(self):
        raw = pd.DataFrame({"URL": ["https://good.com", "https://bad.com", "https://good.com/", "https://conflict.com", "https://conflict.com", "invalid"], "label": [1,0,1,0,1,1]})
        frame, conflicts = prepare_data(raw)
        self.assertEqual(conflicts, 1)
        self.assertEqual(len(frame), 2)
        self.assertEqual(dict(zip(frame.url, frame.target)), {"https://good.com/": 0, "https://bad.com/": 1})

class NetworkTests(SimpleTestCase):
    def test_private_special_addresses_blocked(self):
        for address in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.0.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"]:
            with self.subTest(address=address):
                self.assertFalse(is_public_address(address))
                with self.assertRaises(ScanError):
                    dns_analysis(address)
    @patch("website_scanner.services.dns.resolver.Resolver")
    def test_mixed_dns_blocks_network(self, resolver):
        resolver.return_value.resolve.return_value = [SimpleNamespace(address="8.8.8.8"), SimpleNamespace(address="127.0.0.1")]
        # Answer objects have an rrset attribute.
        resolver.return_value.resolve.return_value = FakeAnswer(resolver.return_value.resolve.return_value)
        with self.assertRaises(ScanError):
            dns_analysis("example.com")
    @patch("website_scanner.services.dns.resolver.Resolver")
    def test_dns_timeout_marked_incomplete(self, resolver):
        resolver.return_value.resolve.side_effect = [FakeAnswer([SimpleNamespace(address="8.8.8.8")]), dns.exception.Timeout(), dns.resolver.NoAnswer(), dns.resolver.NoAnswer(), dns.resolver.NoAnswer(), dns.resolver.NoAnswer()]
        addresses, records = dns_analysis("example.com")
        self.assertEqual(addresses, ["8.8.8.8"])
        self.assertIn("Skipped", records["network_checks"]["status"])
    @patch("website_scanner.services.ssl.create_default_context")
    @patch("website_scanner.services.socket.socket")
    def test_tls_pins_ip_and_verifies_hostname(self, socket_factory, context_factory):
        raw = socket_factory.return_value.__enter__.return_value
        secure = context_factory.return_value.wrap_socket.return_value.__enter__.return_value
        secure.getpeercert.return_value = {"issuer": ((("organizationName", "Test CA"),),), "notAfter": "Jan  1 00:00:00 2030 GMT"}
        secure.version.return_value = "TLSv1.3"
        status, details = check_tls("example.com", "8.8.8.8")
        self.assertEqual(status, "Valid")
        raw.connect.assert_called_once_with(("8.8.8.8", 443))
        context_factory.return_value.wrap_socket.assert_called_once_with(raw, server_hostname="example.com")
        self.assertEqual(details["hostname_verified"], "example.com")
    @patch("website_scanner.services.ssl.create_default_context")
    @patch("website_scanner.services.socket.socket")
    def test_tls_errors_are_not_valid(self, socket_factory, context_factory):
        context_factory.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError("bad certificate")
        self.assertEqual(check_tls("example.com", "8.8.8.8")[0], "Certificate verification failed")
        socket_factory.return_value.__enter__.return_value.connect.side_effect = socket.timeout()
        self.assertEqual(check_tls("example.com", "8.8.8.8")[0], "Unavailable")

class FakeAnswer(list):
    rrset = None

class ReputationRiskTests(SimpleTestCase):
    @patch("website_scanner.reputation.requests.post")
    def test_no_request_without_opt_in(self, post):
        self.assertEqual(check_reputation("https://example.com")[0], "Not requested")
        post.assert_not_called()
    @override_settings(SAFE_BROWSING_API_KEY="")
    @patch("website_scanner.reputation.requests.post")
    def test_no_key_is_not_a_clean_result(self, post):
        self.assertEqual(check_reputation("https://example.com", True)[0], "Not configured")
        post.assert_not_called()
    @override_settings(SAFE_BROWSING_API_KEY="test-only")
    @patch("website_scanner.reputation.requests.post")
    def test_match_and_empty_and_error(self, post):
        response = post.return_value
        response.status_code = 200
        response.json.return_value = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
        self.assertEqual(check_reputation("https://example.com", True)[0], "Threat match")
        response.json.return_value = {}
        self.assertEqual(check_reputation("https://example.com", True)[0], "No known match")
        response.json.side_effect = ValueError("not json")
        self.assertEqual(check_reputation("https://example.com", True)[0], "Unavailable")
    def test_missing_model_or_tls_is_incomplete(self):
        features = extract_url_features("https://example.com/")
        self.assertEqual(assess_risk(features, None, "Valid", "Not configured")[1], "Incomplete assessment")
        self.assertEqual(assess_risk(features, 1, "Unavailable", "Not requested")[1], "Incomplete assessment")
        self.assertEqual(assess_risk(features, 1, "Valid", "Threat match")[:2], (100, "High risk indicators"))

class WebsiteViewTests(TestCase):
    def test_home_and_csrf(self):
        self.assertContains(self.client.get("/website/"), "Website security scanner")
        self.assertEqual(Client(enforce_csrf_checks=True).post("/website/", {"url": "https://example.com"}).status_code, 403)
    @patch("website_scanner.views.check_reputation", return_value=("Not requested", {}))
    @patch("website_scanner.views.predict_phishing", return_value=(20.5, "test-model"))
    @patch("website_scanner.views.check_tls", return_value=("Valid", {"protocol": "TLSv1.3"}))
    @patch("website_scanner.views.dns_analysis", return_value=(["8.8.8.8"], {}))
    def test_saved_result_refresh_does_not_rescan(self, dns, tls, ml, reputation):
        response = self.client.post("/website/", {"url": "https://example.com/a?q=test"}, follow=True)
        self.assertContains(response, "ANALYSIS COMPLETE")
        scan = WebsiteScan.objects.get()
        self.assertEqual(scan.phishing_probability, 20.5)
        self.assertEqual(scan.url_features, extract_url_features(scan.url))
        self.assertEqual(scan.model_version, "test-model")
        self.client.get("/website/")
        self.assertEqual(WebsiteScan.objects.count(), 1)
        dns.assert_called_once()
    @patch("website_scanner.views.check_tls")
    def test_private_url_never_connects(self, tls):
        response = self.client.post("/website/", {"url": "http://127.0.0.1/"})
        self.assertContains(response, "public addresses only")
        tls.assert_not_called()
        self.assertEqual(WebsiteScan.objects.count(), 0)
    @patch("website_scanner.views.check_reputation", return_value=("Not requested", {}))
    @patch("website_scanner.views.predict_phishing", side_effect=FileNotFoundError())
    @patch("website_scanner.views.check_tls")
    @patch("website_scanner.views.dns_analysis", return_value=(["8.8.8.8"], {"network_checks": {"status": "Skipped: incomplete address resolution"}}))
    def test_partial_dns_skips_tls_and_model_unavailable(self, dns, tls, ml, reputation):
        response = self.client.post("/website/", {"url": "https://example.com"}, follow=True)
        self.assertContains(response, "Incomplete assessment")
        tls.assert_not_called()
        self.assertIsNone(WebsiteScan.objects.get().phishing_probability)
