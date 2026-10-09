import unittest
from unittest.mock import call, patch

from vaultcontext_client import auth
from vaultcontext_client import cli


class RateLimitTests(unittest.TestCase):
    def test_query_recovers_after_two_windows(self):
        body = {'sql': 'SELECT id FROM documents'}
        result = {'rows': []}
        with patch.object(auth, 'call', side_effect=[(429, 'private'), (429, 'private'), (200, result)]) as request, patch.object(auth.time, 'sleep') as sleep:
            self.assertEqual(auth.call_read_query({}, body), (200, result))
        self.assertEqual(request.call_args_list, [call({}, 'POST', '/api/context/query', body)] * 3)
        self.assertEqual(sleep.call_args_list, [call(10), call(10)])

    def test_query_exhaustion_is_bounded(self):
        with patch.object(auth, 'call', return_value=(429, 'private')) as request, patch.object(auth.time, 'sleep') as sleep:
            self.assertEqual(auth.call_read_query({}, {}), (429, 'private'))
        self.assertEqual(request.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_other_responses_do_not_retry(self):
        for status in (200, 400, 401, 403, 409, 500):
            with self.subTest(status=status), patch.object(auth, 'call', return_value=(status, {})) as request, patch.object(auth.time, 'sleep') as sleep:
                self.assertEqual(auth.call_read_query({}, {}), (status, {}))
                request.assert_called_once()
                sleep.assert_not_called()

    def test_transport_failure_does_not_retry(self):
        with patch.object(auth, 'call', side_effect=auth.Fail(1, 'transport failed')) as request, patch.object(auth.time, 'sleep') as sleep:
            with self.assertRaises(auth.Fail):
                auth.call_read_query({}, {})
        request.assert_called_once()
        sleep.assert_not_called()

    def test_rate_limit_does_not_check_or_replace_authentication(self):
        with patch.object(auth, 'load_session', return_value={'token': 'synthetic', 'method': 'google'}), patch.object(auth, 'oauth_refresh_needed', return_value=False), patch.object(auth, 'send', return_value=(429, {})) as send, patch.object(auth, 'token_rejected') as rejected:
            self.assertEqual(auth.call({}, 'POST', '/api/context/query', {}), (429, {}))
            send.assert_called_once()
            rejected.assert_not_called()

    def test_action_rate_limit_is_not_replayed_or_disclosed(self):
        with patch.object(auth, 'call', return_value=(429, 'synthetic private response')) as request, patch.object(auth.time, 'sleep') as sleep:
            with self.assertRaises(auth.Fail) as failure:
                cli.action({}, 'save', {})
        request.assert_called_once()
        sleep.assert_not_called()
        self.assertNotIn('synthetic private response', str(failure.exception))


if __name__ == '__main__':
    unittest.main()
