import json
import os
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

import checkin


COOKIE = 'gld:sess=synthetic-private; gld:sess.sig=synthetic-signature'
OTHER = 'gld:sess=second-private; gld:sess.sig=second-signature'
NONCE = 'synthetic-nonce'
OTHER_NONCE = 'another-nonce'
PROOF = '95d98116667d20076de5e31eeba57cb65dac0e9be21afb32263bac1178699533'
PRIVATE_UA = 'SyntheticPrivateBrowser/9.9'


def response(payload, status=200):
    return mock.Mock(status_code=status, **{'json.return_value': payload})


def challenge(nonce=NONCE, ttl=300000):
    return response({'code': 0, 'nonce': nonce, 'ttl': ttl})


class RobustnessTests(unittest.TestCase):
    def setUp(self):
        for patch in (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch(
                'requests.sessions.Session.request',
                side_effect=AssertionError('Live HTTP disabled'),
            ),
            mock.patch('checkin.log'),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def test_proof_matches_official_observe_salt(self):
        proof = checkin.compute_checkin_proof(NONCE)
        self.assertEqual(proof, PROOF)
        self.assertEqual(len(proof), 64)
        self.assertEqual(proof, proof.lower())
        self.assertNotIn(NONCE, proof)

    def test_observe_delay_stays_inside_human_jitter_window(self):
        for forced, expected in ((0, 2.8), (2.8, 2.8), (3.3, 3.3), (4, 4.0), (9, 4.0)):
            with self.subTest(forced=forced):
                with mock.patch('checkin.random.uniform', return_value=forced):
                    self.assertEqual(checkin.checkin_observe_delay(), expected)
        with mock.patch('checkin.random.uniform', side_effect=lambda low, high: (low + high) / 2):
            delay = checkin.checkin_observe_delay()
        self.assertGreaterEqual(delay, checkin.CHECKIN_CHALLENGE_DELAY)
        self.assertGreaterEqual(delay, checkin.CHECKIN_OBSERVE_MIN)
        self.assertLessEqual(delay, checkin.CHECKIN_OBSERVE_MAX)

    def test_beijing_time_is_utc_plus_8(self):
        now = checkin.get_beijing_time()
        self.assertIsNotNone(now.tzinfo)
        self.assertEqual(now.utcoffset(), timedelta(hours=8))
        source = Path(checkin.__file__).read_text(encoding='utf-8')
        self.assertNotIn('.utcnow(', source)
        self.assertIn('sys.exit(main())', source)

    def test_vip_labels_and_expiration(self):
        expected = {
            0: 'Free', 10: 'Free', 11: 'Edu', 21: 'Basic',
            31: 'Pro', 41: 'Team', 51: 'Enterprise',
        }
        for vip, name in expected.items():
            self.assertEqual(checkin.vip_label(vip), name)
        self.assertEqual(checkin.vip_label(None, 'Education'), 'Edu')
        self.assertEqual(checkin.vip_label('41'), 'Team')
        self.assertEqual(checkin.format_points(1.5), '1.5')
        self.assertEqual(checkin.format_points(12), '12')
        self.assertEqual(checkin.format_points('431.50'), '431.5')

        client = checkin.GLaDOS(COOKIE)
        with mock.patch.object(client.session, 'get', return_value=response({
            'code': -101,
            'data': {'email': 'hidden@example.test', 'vip': 31, 'leftDays': 3},
        })):
            self.assertTrue(client.get_status())
        self.assertTrue(client.expired)
        self.assertEqual(client.left_days, '已过期')
        self.assertEqual(client.plan, 'Pro')

        with mock.patch.object(client.session, 'get', return_value=response({
            'code': 0,
            'data': {'leftDays': -101, 'vip': 11},
        })):
            self.assertTrue(client.get_status())
        self.assertTrue(client.expired)
        self.assertEqual(client.plan, 'Edu')

    def test_repeat_checkin_keeps_decimal_points_and_streak(self):
        client = checkin.GLaDOS(COOKIE)
        checkin.apply_checkin_details(client, {
            'code': 1,
            'message': "Today's observation logged.",
            'points': 1.5,
            'streak': 8,
            'list': [{'balance': 431.5}],
        })
        self.assertEqual(client.points_earned, '1.5')
        self.assertEqual(client.points, '431.5')
        self.assertEqual(client.streak, '8')

        repeated = checkin.GLaDOS(COOKIE)
        checkin.apply_checkin_details(repeated, {
            'code': 1,
            'message': 'Checkin Repeats! Please Try Tomorrow',
        })
        self.assertEqual(repeated.points, '?')
        with mock.patch.object(repeated.session, 'get', return_value=response({
            'code': 0,
            'points': 431.5,
            'streak': 9,
            'history': [{'change': 1.5}],
            'plans': {},
        })):
            self.assertTrue(repeated.get_points())
        self.assertEqual(repeated.points, '431.5')
        self.assertEqual(repeated.streak, '9')
        self.assertEqual(repeated.points_change, '+1.5')

    def test_session_reuses_connection_and_omits_get_content_type(self):
        session = checkin.create_session()
        retry = session.get_adapter('https://glados.cloud').max_retries
        self.assertIn('GET', retry.allowed_methods)
        self.assertNotIn('POST', retry.allowed_methods)
        self.assertEqual(retry.total, 1)
        self.assertFalse(session.cookies.get_policy().set_ok(None, None))

        seen = []

        def track_get(url, **kwargs):
            seen.append(url)
            self.assertNotIn('Content-Type', kwargs['headers'])
            return response({'code': 0, 'data': {'leftDays': 1}})

        client = checkin.GLaDOS(COOKIE)
        other = checkin.GLaDOS(COOKIE)
        self.assertIsNot(client.session, other.session)
        with mock.patch.object(client.session, 'get', side_effect=track_get):
            client.req('GET', '/api/user/status')
            client.req('GET', '/api/user/points')
        self.assertEqual(seen, [
            checkin.DOMAINS[0] + '/api/user/status',
            checkin.DOMAINS[0] + '/api/user/points',
        ])

        def track_post(url, **kwargs):
            self.assertIn('Content-Type', kwargs['headers'])
            self.assertEqual(kwargs['headers']['Cookie'], COOKIE)
            return response({'code': 0})

        with mock.patch.object(client.session, 'post', side_effect=track_post):
            client.req('POST', '/api/user/checkin', {'token': 'glados.cloud'})

    @mock.patch('checkin.time.sleep')
    def test_post_timeout_retries_once_with_fresh_nonce(self, sleep):
        client = checkin.GLaDOS(COOKIE)
        client.session.get = mock.Mock(side_effect=[
            challenge(NONCE),
            challenge(OTHER_NONCE),
            challenge('third-nonce'),
        ])
        client.session.post = mock.Mock(side_effect=[
            checkin.requests.ReadTimeout(COOKIE),
            response({'code': 0, 'message': 'Checkin! Got 1 Points'}),
        ])

        result = client.checkin()

        self.assertEqual(result['code'], 0)
        self.assertEqual(client.session.post.call_count, 2)
        sent = [call.kwargs['json'] for call in client.session.post.call_args_list]
        self.assertEqual(sent[0]['nonce'], NONCE)
        self.assertEqual(sent[1]['nonce'], OTHER_NONCE)
        self.assertNotEqual(sent[0]['proof'], sent[1]['proof'])
        self.assertEqual(sent[0]['proof'], PROOF)
        for call in sleep.call_args_list:
            self.assertGreaterEqual(call.args[0], checkin.CHECKIN_OBSERVE_MIN)
            self.assertLessEqual(call.args[0], checkin.CHECKIN_OBSERVE_MAX)
        output = str(checkin.log.call_args_list)
        for secret in (COOKIE, NONCE, OTHER_NONCE, PROOF, sent[1]['proof']):
            self.assertNotIn(secret, output)

    @mock.patch('checkin.time.sleep')
    def test_post_timeout_does_not_retry_more_than_once(self, sleep):
        client = checkin.GLaDOS(COOKIE)
        client.session.get = mock.Mock(return_value=challenge())
        client.session.post = mock.Mock(side_effect=checkin.requests.ReadTimeout(COOKIE))

        result = client.checkin()

        self.assertTrue(result['timed_out'])
        self.assertEqual(result['method'], 'POST')
        self.assertEqual(client.session.post.call_count, 2)
        self.assertEqual(client.session.get.call_count, 2)
        sleep.assert_called()

    @mock.patch('checkin.time.sleep')
    def test_cookie_and_device_failures_skip_the_wait(self, sleep):
        for payload in ({'code': -2, 'message': '没有权限'}, {'code': 4}):
            with self.subTest(payload=payload):
                sleep.reset_mock()
                client = checkin.GLaDOS(COOKIE)
                client.session.get = mock.Mock(return_value=response(payload))
                client.session.post = mock.Mock()
                result, ok = checkin.checkin_with_retry(client, attempts=3, delay_seconds=60)
                self.assertFalse(ok)
                self.assertEqual(result['code'], payload['code'])
                client.session.post.assert_not_called()
                sleep.assert_not_called()
                self.assertTrue(checkin.is_non_retryable_checkin_result(result))
        summary = checkin.summarize_checkin_failure({'code': 4})
        self.assertIn('设备校验', summary)
        self.assertIn('code=4', summary)

    def test_cookie_wrappers_are_removed_and_non_ascii_is_not_logged(self):
        wrapped = '  Cookie: "gld:sess=current; gld:sess.sig=signature"  '
        self.assertEqual(
            checkin.extract_cookie(wrapped),
            'gld:sess=current; gld:sess.sig=signature',
        )
        quoted = "'gld:sess=current; gld:sess.sig=signature'"
        self.assertEqual(checkin.get_session_cookie_kind(checkin.extract_cookie(quoted)), 'gld')

        raw = 'gld:sess=kept-secret; gld:sess.sig=kept-sig\ngld:sess=丢弃秘密; gld:sess.sig=丢弃'
        with mock.patch.dict(os.environ, {'GLADOS_COOKIE': raw}):
            cookies = checkin.get_cookies()
        self.assertEqual(cookies, ['gld:sess=kept-secret; gld:sess.sig=kept-sig'])
        output = str(checkin.log.call_args_list)
        self.assertIn('非 ASCII', output)
        for secret in ('kept-secret', '丢弃秘密', '丢弃'):
            self.assertNotIn(secret, output)

        document = json.dumps([{'name': 'gld:sess', 'value': '秘密'}])
        with mock.patch.dict(os.environ, {'GLADOS_COOKIE': document}):
            self.assertEqual(checkin.get_cookies(), [])

    def test_per_account_user_agent_overrides_shared_value(self):
        shared = 'SharedBrowser/1.0'
        custom = 'User-Agent: "CustomBrowser/2.0"'
        with mock.patch.dict(os.environ, {'GLADOS_USER_AGENT': shared}):
            default_client = checkin.GLaDOS(COOKIE)
            custom_client = checkin.GLaDOS(COOKIE, user_agent=custom)

            def capture(client):
                client.session.get = mock.Mock(return_value=response({'code': 0, 'data': {}}))
                client.req('GET', '/api/user/status')
                return client.session.get.call_args.kwargs['headers']['User-Agent']

            self.assertEqual(capture(default_client), shared)
            self.assertEqual(capture(custom_client), 'CustomBrowser/2.0')
            self.assertNotIn('Content-Type', custom_client.session.get.call_args.kwargs['headers'])

        captured = []

        class Capture(checkin.GLaDOS):
            def __init__(self, cookie, user_agent=None):
                captured.append(user_agent)
                super().__init__(cookie, user_agent=user_agent)
                self.checkin = mock.Mock(return_value={'code': 0, 'message': 'Checkin! Got 1 Point'})
                self.get_status = mock.Mock()
                self.get_points = mock.Mock()

        with mock.patch.dict(os.environ, {
            'GLADOS_COOKIE': COOKIE + '\n' + OTHER,
            'GLADOS_USER_AGENT': shared,
            'GLADOS_USER_AGENT_1': 'FirstBrowser/1.0',
            'EXCHANGE_PLAN': 'off',
        }), mock.patch('checkin.GLaDOS', Capture):
            self.assertEqual(checkin.main(), 0)
        self.assertEqual(captured, ['FirstBrowser/1.0', None])
        output = str(checkin.log.call_args_list)
        self.assertIn('已配置独立值', output)
        self.assertNotIn('FirstBrowser/1.0', output)
        self.assertNotIn(shared, output)

    def test_invalid_per_account_user_agent_fails_without_echoing_it(self):
        with mock.patch.dict(os.environ, {
            'GLADOS_COOKIE': COOKIE,
            'GLADOS_USER_AGENT_1': PRIVATE_UA + '\nBroken',
            'EXCHANGE_PLAN': 'off',
        }), mock.patch('checkin.GLaDOS') as client:
            self.assertEqual(checkin.main(), 1)
        client.assert_not_called()
        output = str(checkin.log.call_args_list)
        self.assertIn('User-Agent 配置错误', output)
        self.assertNotIn(PRIVATE_UA, output)
        self.assertNotIn('synthetic-private', output)

    @mock.patch('checkin.time.sleep')
    @mock.patch('checkin.random.uniform', return_value=12.5)
    def test_schedule_jitter_waits_only_for_schedule_events(self, uniform, sleep):
        client = mock.Mock()
        client.checkin.return_value = {'code': 0, 'message': 'Checkin! Got 1 Point'}
        client.points = '3'
        client.points_change = '?'
        client.left_days = '4'
        client.email = '?'
        client.exchange_info = ''
        client.exchange_result = ''
        for event, expected in (('schedule', True), ('workflow_dispatch', False), ('', False)):
            with self.subTest(event=event):
                sleep.reset_mock()
                uniform.reset_mock()
                env = {
                    'GLADOS_COOKIE': COOKIE,
                    'EXCHANGE_PLAN': 'off',
                    'GITHUB_EVENT_NAME': event,
                }
                with mock.patch.dict(os.environ, env), mock.patch('checkin.GLaDOS', return_value=client):
                    self.assertEqual(checkin.main(), 0)
                if expected:
                    sleep.assert_called_once_with(12.5)
                    uniform.assert_called_once_with(5, 45)
                else:
                    sleep.assert_not_called()
                    uniform.assert_not_called()

    @mock.patch('checkin.time.sleep')
    @mock.patch('checkin.pushplus')
    def test_challenge_auth_failure_exits_nonzero_after_notification(self, push, sleep):
        for code in (-2, 4):
            with self.subTest(code=code):
                push.reset_mock()
                sleep.reset_mock()
                with mock.patch.dict(os.environ, {
                    'GLADOS_COOKIE': COOKIE,
                    'EXCHANGE_PLAN': 'off',
                    'PUSHPLUS_TOKEN': 'synthetic-push-token',
                    'PUSH_LEVEL': 'fail_only',
                }), mock.patch('checkin.requests.Session.get', return_value=response({'code': code})), \
                        mock.patch('checkin.requests.Session.post') as post:
                    self.assertEqual(checkin.main(), 1)
                post.assert_not_called()
                sleep.assert_not_called()
                push.assert_called_once()
                title, content = push.call_args.args[1:]
                self.assertIn('本次运行失败 0/1', title)
                self.assertNotIn(NONCE, content)
                self.assertNotIn('synthetic-private', content)
                self.assertNotIn('synthetic-push-token', content)

    @mock.patch('checkin.time.sleep')
    @mock.patch('checkin.pushplus')
    def test_successful_checkin_report_hides_secrets(self, push, sleep):
        earned_proof = checkin.compute_checkin_proof(NONCE)
        status = response({
            'code': 0,
            'data': {'email': 'hidden@example.test', 'leftDays': 12, 'vip': 41, 'level': 'Team'},
        })
        points = response({
            'code': 0,
            'points': 431.5,
            'streak': 8,
            'history': [{'change': 1.5}],
            'plans': {},
        })
        with mock.patch.dict(os.environ, {
            'GLADOS_COOKIE': COOKIE,
            'EXCHANGE_PLAN': 'off',
            'PUSHPLUS_TOKEN': 'synthetic-push-token',
            'PUSH_LEVEL': 'all',
        }), mock.patch('checkin.requests.Session.get', side_effect=[challenge(), status, points]), \
                mock.patch('checkin.requests.Session.post', return_value=response({
                    'code': 0,
                    'message': 'Checkin! Got 1 Points',
                    'points': 1.5,
                    'streak': 8,
                    'list': [{'balance': 431.5}],
                })):
            self.assertEqual(checkin.main(), 0)

        push.assert_called_once()
        content = push.call_args.args[2]
        self.assertIn('Team', content)
        self.assertIn('431.5', content)
        self.assertIn('8 天', content)
        self.assertIn('+1.5', content)
        self.assertIn('hidden@example.test', content)
        output = str(checkin.log.call_args_list)
        self.assertIn('431.5', output)
        self.assertIn('Team', output)
        for secret in (NONCE, earned_proof, 'synthetic-private', 'hidden@example.test', 'synthetic-push-token'):
            self.assertNotIn(secret, output)


if __name__ == '__main__':
    unittest.main()
