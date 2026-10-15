import unittest
from unittest import mock

from curl_cffi.requests import Headers

from services.openai_backend_api import InvalidAccessTokenError, OpenAIBackendAPI


class CloudflareRetryTests(unittest.TestCase):
    def setUp(self):
        self.api = OpenAIBackendAPI("")
        self.addCleanup(self.api.close)

    def response(self, status=403, headers=None, payload=None):
        response = mock.Mock(status_code=status, headers=Headers(headers or {}))
        response.json.return_value = payload or {}
        return response

    def test_only_challenge_403_is_retryable(self):
        cases = [
            (403, {"CF-Mitigated": "challenge"}, True),
            (403, {"Content-Type": "text/html; charset=utf-8"}, True),
            (403, {"Content-Type": "application/json"}, False),
            (403, {"Content-Type": "application/problem+json", "CF-Mitigated": "challenge"}, False),
            (403, {"Content-Type": "text/plain"}, False),
            (403, {}, False),
            (401, {"Content-Type": "text/html", "CF-Mitigated": "challenge"}, False),
            (200, {"Content-Type": "text/html", "CF-Mitigated": "challenge"}, False),
        ]
        for status, headers, expected in cases:
            with self.subTest(status=status, headers=headers):
                self.assertEqual(self.api._is_cloudflare_challenge(self.response(status, headers)), expected)

    def test_all_refresh_endpoints_recover_after_two_challenges(self):
        cases = [
            ("_get_me", "get", "/backend-api/me"),
            ("_get_conversation_init", "post", "/backend-api/conversation/init"),
            ("_get_default_account", "get", "/backend-api/accounts/check/v4-2023-04-27"),
        ]
        for method, verb, path in cases:
            with (
                self.subTest(path=path),
                mock.patch.object(self.api.session, verb, side_effect=[
                    self.response(headers={"CF-Mitigated": "challenge"}),
                    self.response(headers={"Content-Type": "text/html"}),
                    self.response(200),
                ]) as request,
                mock.patch("services.openai_backend_api.time.sleep") as sleep,
            ):
                self.assertEqual(getattr(self.api, method)(), {})
                self.assertEqual(request.call_count, 3)
                self.assertEqual(sleep.call_args_list, [mock.call(1.5), mock.call(3.0)])
                for call in request.call_args_list:
                    self.assertEqual(call.kwargs["headers"]["X-OpenAI-Target-Path"], path)
                    self.assertEqual(call.kwargs["headers"]["X-OpenAI-Target-Route"], path)
                    self.assertEqual(call, request.call_args_list[0])

    def test_exhausted_challenge_raises_after_three_attempts(self):
        with (
            mock.patch.object(self.api.session, "get", return_value=self.response(
                headers={"Content-Type": "text/html"})) as request,
            mock.patch("services.openai_backend_api.time.sleep") as sleep,
        ):
            with self.assertRaisesRegex(RuntimeError, r"/backend-api/me failed: HTTP 403"):
                self.api._get_me()
        self.assertEqual(request.call_count, 3)
        self.assertEqual(sleep.call_args_list, [mock.call(1.5), mock.call(3.0)])

    def test_json_403_and_401_fail_without_retry_on_all_refresh_endpoints(self):
        for method, verb in (("_get_me", "get"), ("_get_conversation_init", "post"),
                             ("_get_default_account", "get")):
            for status, error in ((403, RuntimeError), (401, InvalidAccessTokenError)):
                with (
                    self.subTest(method=method, status=status),
                    mock.patch.object(self.api.session, verb, return_value=self.response(
                        status, {"Content-Type": "application/json"})) as request,
                    mock.patch("services.openai_backend_api.time.sleep") as sleep,
                ):
                    with self.assertRaises(error):
                        getattr(self.api, method)()
                    request.assert_called_once()
                    sleep.assert_not_called()

    def test_json_rejection_after_challenge_stops_retrying(self):
        with (
            mock.patch.object(self.api.session, "get", side_effect=[
                self.response(headers={"CF-Mitigated": "challenge"}),
                self.response(headers={"Content-Type": "application/json"}),
                self.response(200),
            ]) as request,
            mock.patch("services.openai_backend_api.time.sleep") as sleep,
        ):
            with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
                self.api._get_me()
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(1.5)


if __name__ == "__main__":
    unittest.main()
