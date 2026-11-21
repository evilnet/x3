"""Tests for tools/bind-keycloak-ids.py.

Run from the top of the x3 tree:  python3 -m unittest tools/test_bind_keycloak_ids.py
Needs only Python 3; no Keycloak (the lookups are faked).
"""

import contextlib
import errno
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'bind-keycloak-ids.py')
DATA = os.path.join(HERE, 'testdata')
FIXTURE_DB = os.path.join(DATA, 'x3.db')
FIXTURE_CONF = os.path.join(DATA, 'x3.conf')


def _load():
    spec = importlib.util.spec_from_file_location('bind_keycloak_ids', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bki = _load()

ALICE_UUID = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'
ALICE_ID = 'a6e4EJ2tEdGAtADAT9QwyA'
BOB_UUID = '0f3c2a10-1111-4222-8333-444455556666'      # bob's stored id in the fixture
CAROL_STORED = 'mot8bQAAQACAAAAAAAAAAQ'                 # carol's stored id in the fixture
CAROL_KC_UUID = '11111111-2222-4333-8444-555555555555'  # Keycloak's carol: a different user
DAVE_UUID = '22222222-3333-4444-8555-666666666666'
OTHER_UUID = '33333333-4444-4555-8666-777777777777'

DEFAULT_PROFILE = {'attributes': [{'name': 'username', 'validations': {
    'length': {'min': 2, 'max': 30},
    'username-prohibited-characters': {},
}}]}


def read_fixture(path=FIXTURE_DB):
    with open(path, 'rb') as f:
        return f.read().decode('latin-1')


def fake_lookup(users=None, failing=()):
    """users: {name: [uuid, ...]} -- each becomes a Keycloak user with that username."""
    users = users or {}
    calls = []

    def lookup(name):
        calls.append(name)
        if name in failing:
            raise OSError('connection refused')
        return [{'id': u, 'username': username}
                for username, ids in users.items()
                if bki.irc_fold(username) == bki.irc_fold(name)
                for u in ids]
    lookup.calls = calls
    return lookup


def default_rules():
    return bki.realm_username_rules(lambda: DEFAULT_PROFILE)


def fixture_users():
    return {'alice': [ALICE_UUID], 'bob': [BOB_UUID], 'carol': [CAROL_KC_UUID],
            'dave': [DAVE_UUID]}


class FakeKeycloak:
    """Stands in for the real Keycloak client in main()."""

    def __init__(self, users=None, profile=DEFAULT_PROFILE, failing=()):
        self.lookup = fake_lookup(users, failing)
        self._profile = profile
        self.settings = None

    def check(self):
        pass

    def profile(self):
        if self._profile is None:
            raise bki.RequestRefused('GET users/profile', 403)
        return self._profile


def run_main(argv, keycloak):
    out, err = io.StringIO(), io.StringIO()

    def connect(settings):
        keycloak.settings = settings
        return keycloak
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = bki.main(argv, connect=connect)
    return code, out.getvalue(), err.getvalue()


def snapshot(directory):
    result = {}
    for name in sorted(os.listdir(directory)):
        with open(os.path.join(directory, name), 'rb') as f:
            result[name] = f.read()
    return result


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='bki-test-')
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = os.path.join(self.tmp, 'x3.db')
        self.conf = os.path.join(self.tmp, 'x3.conf')
        shutil.copyfile(FIXTURE_DB, self.db)
        shutil.copyfile(FIXTURE_CONF, self.conf)


class CompactIdTest(unittest.TestCase):
    def test_compact_id_matches_x3(self):
        self.assertEqual(bki.compact_id('6ba7b810-9dad-11d1-80b4-00c04fd430c8'), 'a6e4EJ2tEdGAtADAT9QwyA')

    def test_compact_id_refuses_what_kcid_from_uuid_refuses(self):
        for bad in ('', '6ba7b810', '6ba7b810-9dad-11d1-80b4-00c04fd430c8aa', 'zba7b810-9dad-11d1-80b4-00c04fd430c8'):
            with self.assertRaises(ValueError, msg=bad):
                bki.compact_id(bad)


class ParseTest(unittest.TestCase):
    def test_parse_reads_what_x3_writes(self):
        db = bki.parse(read_fixture())
        handles = db.get('NickServ')
        self.assertIsInstance(handles, bki.Obj)
        alice = handles.get('ALICE')                  # keys are found under IRC folding, as X3 does
        self.assertEqual(alice.get('info').value, 'says "hi"\tand\\leaves')
        self.assertEqual(alice.get('masks').items, ['*@*', '*@example.org'])
        self.assertEqual(handles.get('old[one]').get('masks').items, [])
        cookie = handles.get('OLD{ONE}').get('cookie')
        self.assertEqual(cookie.get('type').value, 'activation')
        users = db.get('ChanServ').get('channels').get('#test').get('users')
        self.assertEqual(users.get('alice').get('level').value, '500')
        self.assertEqual(db.get('AuthServ').items, ['NickServ', 'modcmd'])
        # each object remembers the offset just after its own '{'
        text = read_fixture()
        self.assertEqual(text[alice.offset - 1], '{')
        self.assertTrue(text[:alice.offset].endswith('"alice" {'))
        # a conf, with both kinds of comment
        conf = bki.parse(read_fixture(FIXTURE_CONF))
        self.assertEqual(conf.get_path('services/nickserv/valid_account_regex').value, '^[-_a-z0-9A-Z]{2,15}$')

    def test_parse_follows_recdb_details(self):
        p = bki.parse
        self.assertEqual(p('"k" = "v";').get('k').value, 'v')                       # optional '='
        self.assertEqual(p('"a"{"b""1";};').get('a').get('b').value, '1')           # no whitespace at all
        self.assertEqual(p('"l" ("x",);').get('l').items, ['x'])                    # one trailing comma
        self.assertEqual(p('"k" "\\101\\1018\\778\\x41\\x4\\xg\\q";').get('k').value,
                         'AA8?8A\x04\\xg\\q')                                       # octal, hex, unknown escapes
        self.assertEqual(p('"k" "a\\0b";').get('k').value, 'a')                     # a C string ends at NUL
        self.assertEqual(p('/*a**/b*/"k" "v";').get('k').value, 'v')                # recdb.c's star handling
        self.assertEqual(p('"k" "1"; "K" "2";').get('k').value, '2')                # last one wins
        self.assertEqual(len(p('').entries), 0)

    def test_parse_refuses_what_recdb_refuses(self):
        cases = [
            ('"k" "v";\n"bad" "unterminated;\n', 2),   # unterminated string (raw newline)
            ('"k" "v";\n"k2" "v2"\n"k3" "v3";\n', 3),  # missing ';' (found at the next record)
            ('"k" "v";\n"o" { "a" "b";\n', 2),          # object never closed
            ('"k" "v";\n\n"l" ("a" "b");\n', 3),        # list without a comma
            ('"k" "v";\n"l" (,);\n', 2),                 # leading comma
            ('"k" ?;', 1),                               # not a record value
            ('"k"', 1),                                  # name without a value
            ('"k" "v"; /* dangling', 1),                 # recdb.c would never finish reading this
        ]
        for text, line in cases:
            with self.assertRaises(bki.ParseError, msg=text) as caught:
                bki.parse(text)
            self.assertEqual(caught.exception.line, line, text)
            self.assertIn('line %d' % line, str(caught.exception))


class FoldTest(unittest.TestCase):
    def test_irc_fold_is_x3s(self):
        self.assertEqual(bki.irc_fold('Foo[1]\\^'), 'foo{1}|~')
        self.assertEqual(bki.irc_fold('\xc0\xde\xd7'), '\xe0\xfe\xd7')   # tools_init's Latin-1 range, not the multiply sign


class BindTest(unittest.TestCase):
    def bind_text(self, text, users=None, failing=(), rule=None, rules=None):
        lookup = fake_lookup(users, failing)
        report = bki.bind(bki.parse(text), lookup, rule, rules or default_rules())
        return report, lookup

    def test_binds_an_unbound_handle_with_one_user(self):
        report, _ = self.bind_text('"NickServ" { "alice" { "lastseen" "1"; }; };', {'alice': [ALICE_UUID]})
        self.assertEqual(report.bound, {'alice': ALICE_ID})
        self.assertEqual((report.already_bound, report.no_user, report.ambiguous, report.errors), (0, [], [], []))

    def test_name_matched_under_irc_folding(self):
        report, _ = self.bind_text('"NickServ" { "Foo[1]" { "lastseen" "1"; }; };', {'foo{1}': [ALICE_UUID]})
        self.assertEqual(report.bound, {'Foo[1]': ALICE_ID})

    def test_a_returned_user_of_another_name_is_not_taken(self):
        lookup = lambda name: [{'id': ALICE_UUID, 'username': 'someone-else'}]
        report = bki.bind(bki.parse('"NickServ" { "alice" { }; };'), lookup, None, default_rules())
        self.assertEqual(report.bound, {})
        self.assertEqual([n.handle for n in report.no_user], ['alice'])

    def test_bound_handle_is_left_alone_and_a_different_id_is_reported(self):
        text = read_fixture()
        report, _ = self.bind_text(text, fixture_users())
        self.assertNotIn('bob', report.bound)
        self.assertNotIn('carol', report.bound)
        self.assertEqual(report.already_bound, 1)                      # bob: same id
        self.assertEqual([tuple(m) for m in report.mismatched],
                         [('carol', CAROL_STORED, bki.compact_id(CAROL_KC_UUID))])
        out = bki.write_bound(text, bki.parse(text), report.bound)
        self.assertEqual(out.count('"kc_id" "mot8bQAAQACAAAAAAAAAAQ"'), 1)
        self.assertEqual(out.count('"kc_id" "DzwqEBERQiKDM0REVVVmZg"'), 1)

    def test_no_user_is_left_unbound(self):
        report, _ = self.bind_text('"NickServ" { "alice" { }; };', {})
        self.assertEqual(report.bound, {})
        self.assertEqual(len(report.no_user), 1)
        self.assertEqual(report.no_user[0].handle, 'alice')
        self.assertIs(report.no_user[0].name_allowed, True)

    def test_no_user_with_a_name_keycloak_refuses(self):
        rule = bki.read_name_rule(bki.parse('"services" { "nickserv" { "valid_account_regex" "^[-_a-z0-9A-Z]{2,15}$"; }; };'))
        report, _ = self.bind_text('"NickServ" { "Foo[1]" { }; "x" { }; "fine" { }; };', {}, rule=rule)
        allowed = {n.handle: n.name_allowed for n in report.no_user}
        self.assertEqual(allowed, {'Foo[1]': False, 'x': False, 'fine': True})
        matches = {n.handle: n.matches_rule for n in report.no_user}
        self.assertEqual(matches, {'Foo[1]': False, 'x': False, 'fine': True})

    def test_prohibited_list_matches_keycloak_26_4(self):
        rules = default_rules()
        for ch in '[]\\^{|}`~!$%&*()=,;:\'"/?#<> ':
            self.assertFalse(bki.keycloak_allows('ab' + ch + 'cd', rules), repr(ch))
        for ch in '-_.@+':
            self.assertTrue(bki.keycloak_allows('ab' + ch + 'cd', rules), repr(ch))
        for ch in '\t\x01\x7f':
            self.assertFalse(bki.keycloak_allows('ab' + ch + 'cd', rules), repr(ch))

    def test_realm_rules_are_applied_as_configured(self):
        rules = default_rules()
        self.assertEqual(rules.source, 'realm')
        self.assertFalse(bki.keycloak_allows('a', rules))
        self.assertTrue(bki.keycloak_allows('a' * 30, rules))
        self.assertFalse(bki.keycloak_allows('a' * 31, rules))
        with_pattern = bki.realm_username_rules(lambda: {'attributes': [{'name': 'username', 'validations': {
            'length': {'min': 2, 'max': 30}, 'pattern': {'pattern': '^[a-z]+$', 'error-message': 'no'}}}]})
        self.assertFalse(bki.keycloak_allows('ab1', with_pattern))
        self.assertTrue(bki.keycloak_allows('abc', with_pattern))
        # without username-prohibited-characters in the profile, "a[b" is not refused on that account
        length_only = bki.realm_username_rules(
            lambda: {'attributes': [{'name': 'username', 'validations': {'length': {'min': '2', 'max': '30'}}}]})
        self.assertTrue(bki.keycloak_allows('a[b', length_only))
        self.assertFalse(bki.keycloak_allows('a[b', rules))
        self.assertEqual(length_only.unchecked, [])

    def test_unknown_username_validator_is_reported(self):
        rules = bki.realm_username_rules(lambda: {'attributes': [
            {'name': 'email', 'validations': {'email': {}}},
            {'name': 'username', 'validations': {'length': {'min': 2, 'max': 30},
                                                 'username-prohibited-characters': {},
                                                 'my-custom-rule': {}}}]})
        report = bki.bind(bki.parse('"NickServ" { };'), fake_lookup(), None, rules)
        self.assertEqual(report.unchecked_validators, ['my-custom-rule'])
        self.assertEqual(report.rules_source, 'realm')

    def test_two_matching_users_is_refused(self):
        text = '"NickServ" { "alice" { "lastseen" "1"; }; };'
        report, _ = self.bind_text(text, {'alice': [ALICE_UUID], 'ALICE': [OTHER_UUID]})
        self.assertEqual(report.bound, {})
        self.assertEqual([a.handle for a in report.ambiguous], ['alice'])
        self.assertEqual(bki.write_bound(text, bki.parse(text), report.bound), text)

    def test_failed_lookup_changes_nothing(self):
        text = '"NickServ" { "alice" { "lastseen" "1"; }; "bob" { }; };'
        report, _ = self.bind_text(text, {'alice': [ALICE_UUID], 'bob': [BOB_UUID]}, failing=('alice',))
        self.assertEqual(report.bound, {'bob': bki.compact_id(BOB_UUID)})
        self.assertEqual([e.handle for e in report.errors], ['alice'])
        self.assertIn('connection refused', report.errors[0].error)
        out = bki.write_bound(text, bki.parse(text), report.bound)
        self.assertIn('"alice" { "lastseen" "1"; }', out)

    def test_an_id_already_stored_elsewhere_is_not_bound_again(self):
        # Keycloak's "newname" is the user whose id "oldname" already holds (a rename in Keycloak).
        text = '"NickServ" { "oldname" { "kc_id" "%s"; }; "newname" { }; };' % ALICE_ID
        report, _ = self.bind_text(text, {'newname': [ALICE_UUID]})
        self.assertEqual(report.bound, {})
        self.assertEqual([e.handle for e in report.errors], ['newname'])
        self.assertIn('oldname', report.errors[0].error)

    def test_a_kc_id_that_is_not_a_string_is_not_overridden(self):
        # X3 reads the last "kc_id" and only as a string; a key inserted in front would not win.
        report, _ = self.bind_text('"NickServ" { "alice" { "KC_ID" ("x"); }; };', {'alice': [ALICE_UUID]})
        self.assertEqual(report.bound, {})
        self.assertEqual([e.handle for e in report.errors], ['alice'])

    def test_name_rule_prefers_handle_regex(self):
        both = bki.read_name_rule(bki.parse(
            '"services" { "nickserv" { "valid_account_regex" "^a$"; "valid_handle_regex" "^b$"; }; };'))
        self.assertEqual((both.source, both.pattern), ('valid_handle_regex', '^b$'))
        rule = bki.read_name_rule(bki.parse(
            '"services" { "nickserv" { "valid_account_regex" "^[-_a-z0-9A-Z]{2,15}$"; }; };'))
        self.assertEqual((rule.source, rule.pattern), ('valid_account_regex', '^[-_a-z0-9A-Z]{2,15}$'))
        self.assertTrue(rule.test('Foo_1'))
        self.assertFalse(rule.test('foo`1'))
        self.assertTrue(rule.test('FOO'))
        none = bki.read_name_rule(bki.parse('"services" { "nickserv" { }; };'))
        self.assertEqual(none.source, 'none')
        self.assertTrue(none.test('Foo-_9'))
        self.assertFalse(none.test('foo.bar'))
        # searched, not anchored, and case-insensitive, as regexec with REG_ICASE does
        self.assertTrue(bki.read_name_rule(bki.parse(
            '"services" { "nickserv" { "valid_handle_regex" "OO"; }; };')).test('xfoox'))

    def test_handles_outside_the_current_rule_are_listed(self):
        rule = bki.read_name_rule(bki.parse(read_fixture(FIXTURE_CONF)))
        report = bki.bind(bki.parse(read_fixture()), fake_lookup(fixture_users()), rule, default_rules())
        self.assertEqual(report.outside_name_rule, ['old[one]'])
        self.assertEqual(report.name_rule, ('valid_account_regex', '^[-_a-z0-9A-Z]{2,15}$'))

    def test_untranslatable_pattern_is_an_error(self):
        for pattern in ('^[[:alnum:]]+$', '^[[.hyphen.]a]+$', '^\\w+$', '^[a\\]]+$', '(?i)^a$', '^a*?$', '*a'):
            conf = bki.parse('"services" { "nickserv" { "valid_handle_regex" "%s"; }; };'
                             % pattern.replace('\\', '\\\\'))
            with self.assertRaises(bki.NameRuleError, msg=pattern) as caught:
                bki.read_name_rule(conf)
            self.assertIn(pattern, str(caught.exception))

    def test_settings_come_from_the_conf(self):
        settings = bki.keycloak_settings(bki.parse(read_fixture(FIXTURE_CONF)))
        self.assertEqual(settings, {'url': 'http://keycloak.invalid:8080', 'realm': 'fixture-realm',
                                    'client_id': 'fixture-client', 'secret': 'fixture-secret-do-not-print'})
        self.assertEqual(bki.nickserv_section(bki.parse(read_fixture(FIXTURE_CONF))), 'NickServ')

    def test_profile_refused_falls_back_to_defaults(self):
        def refused():
            raise bki.RequestRefused('GET users/profile', 403)
        self.assertIsNone(bki.realm_username_rules(refused))
        rules = bki.default_username_rules(2, 30)
        report = bki.bind(bki.parse('"NickServ" { "a" { }; };'), fake_lookup(), None, rules)
        self.assertEqual(report.rules_source, 'default')
        self.assertIs(report.no_user[0].name_allowed, False)
        self.assertFalse(bki.keycloak_allows('a[b', rules))


class ReplacedIdTest(unittest.TestCase):
    """REBIND * moves kc_id into kc_id_prev on purpose; X3 refuses such an id."""

    def bind_text(self, text, users):
        return bki.bind(bki.parse(text), fake_lookup(users), None, default_rules())

    def test_replaced_id_string_form_is_not_bound(self):
        text = '"NickServ" { "alice" { "kc_id_prev" "%s"; "lastseen" "1"; }; };' % ALICE_ID
        report = self.bind_text(text, {'alice': [ALICE_UUID]})
        self.assertEqual(report.bound, {})
        self.assertEqual([tuple(r) for r in report.replaced_id], [('alice', ALICE_ID)])
        self.assertTrue(report.needs_a_look())
        self.assertEqual(bki.write_bound(text, bki.parse(text), report.bound), text)

    def test_replaced_id_list_form_is_not_bound(self):
        # newest first, as X3 writes it; an entry in UUID form is compared after normalising
        for prev in ('("%s", "%s")' % (bki.compact_id(OTHER_UUID), ALICE_ID),
                     '("%s", "%s")' % (bki.compact_id(OTHER_UUID), ALICE_UUID)):
            report = self.bind_text('"NickServ" { "alice" { "kc_id_prev" %s; }; };' % prev,
                                    {'alice': [ALICE_UUID]})
            self.assertEqual(report.bound, {}, prev)
            self.assertEqual([tuple(r) for r in report.replaced_id], [('alice', ALICE_ID)], prev)

    def test_a_replaced_id_list_without_the_candidate_binds(self):
        report = self.bind_text('"NickServ" { "alice" { "kc_id_prev" ("%s", "%s"); }; };'
                                % (bki.compact_id(OTHER_UUID), bki.compact_id(BOB_UUID)), {'alice': [ALICE_UUID]})
        self.assertEqual(report.bound, {'alice': ALICE_ID})
        self.assertEqual(report.replaced_id, [])

    def test_a_malformed_kc_id_prev_is_an_error(self):
        text = '"NickServ" { "alice" { "kc_id_prev" { "x" "y"; }; }; };'
        report = self.bind_text(text, {'alice': [ALICE_UUID]})
        self.assertEqual(report.bound, {})
        self.assertEqual([e.handle for e in report.errors], ['alice'])
        self.assertIn('kc_id_prev', report.errors[0].error)


class StubKeycloak(bki.KeycloakClient):
    """The real client with its HTTP layer (_open) replaced: a token, and an
    exact username search that ignores letter case, as Keycloak's does."""

    def __init__(self, users):
        super().__init__({'url': 'http://kc.stub', 'realm': 'r', 'client_id': 'c', 'secret': 's'})
        self.users = users              # [(username, uuid)]
        self.queries = []

    def _open(self, request, what):
        url = urllib.parse.urlsplit(request.full_url)
        if url.path.endswith('/protocol/openid-connect/token'):
            return {'access_token': 'token', 'expires_in': 300}
        self.queries.append(url.query)
        query = urllib.parse.parse_qs(url.query)
        if query.get('exact') != ['true']:
            raise AssertionError('the user search must be exact: %s' % url.query)
        name = query['username'][0]
        return [{'id': uuid, 'username': username} for username, uuid in self.users
                if username.lower() == name.lower()]


class RealLookupTest(unittest.TestCase):
    def test_real_lookup_finds_the_other_bracket_spelling(self):
        keycloak = StubKeycloak([('foo{1}', ALICE_UUID)])
        self.assertEqual(keycloak.lookup('Foo[1]'), [{'id': ALICE_UUID, 'username': 'foo{1}'}])
        self.assertEqual(len(keycloak.queries), 4)            # [ and ] each have two spellings
        self.assertIn('username=Foo%5B1%5D&exact=true&briefRepresentation=true', keycloak.queries)
        self.assertIn('username=Foo%7B1%7D&exact=true&briefRepresentation=true', keycloak.queries)
        report = bki.bind(bki.parse('"NickServ" { "Foo[1]" { }; };'), StubKeycloak([('foo{1}', ALICE_UUID)]).lookup,
                          None, default_rules())
        self.assertEqual(report.bound, {'Foo[1]': ALICE_ID})

    def test_real_lookup_returns_users_of_every_spelling(self):
        keycloak = StubKeycloak([('foo[1]', ALICE_UUID), ('foo{1}', OTHER_UUID), ('a|b', BOB_UUID)])
        self.assertEqual(sorted(u['id'] for u in keycloak.lookup('foo[1]')), sorted([ALICE_UUID, OTHER_UUID]))
        self.assertEqual([u['id'] for u in keycloak.lookup('A\\B')], [BOB_UUID])
        report = bki.bind(bki.parse('"NickServ" { "foo[1]" { }; };'), keycloak.lookup, None, default_rules())
        self.assertEqual(report.bound, {})
        self.assertEqual([a.handle for a in report.ambiguous], ['foo[1]'])

    def test_real_lookup_merges_a_user_seen_twice(self):
        class Repeating(StubKeycloak):
            def _open(self, request, what):
                answer = super()._open(request, what)
                return answer if isinstance(answer, dict) else [{'id': ALICE_UUID, 'username': 'x[y'}]
        self.assertEqual(Repeating([]).lookup('x[y'), [{'id': ALICE_UUID, 'username': 'x[y'}])

    def test_real_lookup_refuses_a_name_over_the_cap(self):
        keycloak = StubKeycloak([('alice', ALICE_UUID)])
        self.assertEqual(len(bki.fold_spellings('[]{}|^')), 64)
        over = ['a[]{}|^~', 'b[[[[[[[', 'c~~~~~~~', 'd\\\\\\\\\\\\\\', 'e]]]]]]]', 'f}}}}}}}']
        text = '"NickServ" { %s "alice" { }; };' % ''.join('"%s" { };' % n.replace('\\', '\\\\') for n in over)
        report = bki.bind(bki.parse(text), keycloak.lookup, None, default_rules())
        self.assertEqual([e.handle for e in report.errors], over)
        for e in report.errors:
            self.assertIn('more than 6', e.error)
        self.assertEqual(report.bound, {'alice': ALICE_ID})   # six refusals are not Keycloak failures
        self.assertEqual(keycloak.queries, ['username=alice&exact=true&briefRepresentation=true'])


class WriteTest(unittest.TestCase):
    def test_output_differs_only_by_inserted_kc_id_lines(self):
        text = read_fixture()
        db = bki.parse(text)
        report = bki.bind(db, fake_lookup(fixture_users()), None, default_rules())
        self.assertEqual(report.bound, {'alice': ALICE_ID, 'dave': bki.compact_id(DAVE_UUID)})
        out = bki.write_bound(text, db, report.bound)
        self.assertNotEqual(out, text)
        # X3 writes a handle on one line: the entry goes in right after "{", on that line ...
        self.assertIn('"alice" { "kc_id" "%s"; "email_addr"' % ALICE_ID, out)
        # ... and a handle written one entry per line gets a line of its own.
        self.assertIn('"dave" {\n\t"kc_id" "%s";\n\t"email_addr"' % bki.compact_id(DAVE_UUID), out)
        stripped = out
        for kc_id in report.bound.values():
            self.assertNotIn(kc_id, text)
            stripped, count = re.subn(r'(?:\n[ \t]*| )"kc_id" "%s";' % re.escape(kc_id), '', stripped)
            self.assertEqual(count, 1)
        self.assertEqual(stripped, text)
        bki.verify_output(db, out, report.bound)   # and the tree check agrees

    def test_verification_refuses_any_other_change(self):
        text = read_fixture()
        db = bki.parse(text)
        bound = {'alice': ALICE_ID}
        good = bki.write_bound(text, db, bound)
        bki.verify_output(db, good, bound)
        for bad in (good.replace('"flags" "c"; "info"', '"flags" "d"; "info"'),   # a value changed
                    good.replace('"kc_id" "%s"; ' % ALICE_ID, ''),                # the entry missing
                    good.replace('"dave" {', '"dave" { "kc_id" "%s";' % ALICE_ID),  # one more entry
                    good.replace('"register" "1785999495"; };\n"bob"', '};\n"bob"'),
                    good[:-30]):                                                  # cut short
            with self.assertRaises(bki.VerifyError):
                bki.verify_output(db, bad, bound)


class ReportListsTest(unittest.TestCase):
    """What the report lists beyond the bindings it makes."""

    def bind_text(self, text, users=None):
        return bki.bind(bki.parse(text), fake_lookup(users), None, default_rules())

    def test_a_bound_handle_whose_keycloak_user_is_gone_is_listed(self):
        report = self.bind_text('"NickServ" { "alice" { "kc_id" "%s"; }; };' % ALICE_ID, {})
        self.assertEqual(report.already_bound, 0)
        self.assertEqual([tuple(b) for b in report.bound_no_user], [('alice', ALICE_ID)])
        self.assertTrue(report.needs_a_look())

    def test_handles_sharing_a_kc_id_are_reported(self):
        report = self.bind_text('"NickServ" { "alice" { "kc_id" "%s"; }; "bob" { "kc_id" "%s"; }; '
                                '"carol" { "kc_id" "%s"; }; };' % (ALICE_ID, ALICE_ID, CAROL_STORED),
                                {'alice': [ALICE_UUID], 'carol': [CAROL_KC_UUID]})
        self.assertEqual([(s.id, list(s.handles)) for s in report.shared_id], [(ALICE_ID, ['alice', 'bob'])])
        self.assertTrue(report.needs_a_look())

    def test_no_user_entries_carry_the_opserv_level(self):
        report = self.bind_text('"NickServ" { "oper1" { "opserv_level" "900"; }; "plain" { }; '
                                '"odd" { "opserv_level" "x"; }; };', {})
        self.assertEqual({n.handle: n.opserv_level for n in report.no_user}, {'oper1': 900, 'plain': 0, 'odd': 0})


class CommandLineTest(TempDirTest):
    def test_refuses_to_overwrite_its_input(self):
        before = snapshot(self.tmp)
        for out in (self.db, os.path.join(self.tmp, '.', 'x3.db'), self.conf):
            proc = subprocess.run([sys.executable, SCRIPT, '--db', self.db, '--conf', self.conf, '--out', out],
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn('--out', proc.stderr)
        link = os.path.join(self.tmp, 'link.db')
        os.symlink(self.db, link)
        proc = subprocess.run([sys.executable, SCRIPT, '--db', self.db, '--conf', self.conf, '--out', link],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        os.unlink(link)
        self.assertEqual(snapshot(self.tmp), before)

    def test_refuses_an_existing_out_file(self):
        existing = os.path.join(self.tmp, 'exists.db')
        with open(existing, 'w') as f:
            f.write('keep me')
        code, _, err = run_main(['--db', self.db, '--conf', self.conf, '--out', existing],
                                FakeKeycloak(fixture_users()))
        self.assertEqual(code, 1)
        with open(existing) as f:
            self.assertEqual(f.read(), 'keep me')

    def test_without_out_nothing_is_written(self):
        before = snapshot(self.tmp)
        code, out, err = run_main(['--db', self.db, '--conf', self.conf], FakeKeycloak(fixture_users()))
        self.assertEqual(code, 2, err)           # carol mismatched, old[one] has no user
        self.assertEqual(snapshot(self.tmp), before)
        self.assertIn('handles total: 5', out)
        self.assertIn('bound now: 2', out)

    def test_out_writes_a_new_verified_file(self):
        target = os.path.join(self.tmp, 'x3.db.bound')
        report_path = os.path.join(self.tmp, 'report.json')
        code, out, err = run_main(['--db', self.db, '--conf', self.conf, '--out', target, '--json', report_path],
                                  FakeKeycloak(fixture_users()))
        self.assertEqual(code, 2, err)
        self.assertEqual(read_fixture(self.db), read_fixture())     # input untouched
        new = read_fixture(target)
        handles = bki.parse(new).get('NickServ')
        self.assertEqual(handles.get('alice').get('kc_id').value, ALICE_ID)
        self.assertEqual(handles.get('dave').get('kc_id').value, bki.compact_id(DAVE_UUID))
        self.assertIsNone(handles.get('old[one]').get('kc_id'))
        with open(report_path) as f:
            self.assertIn('"already_bound": 1', f.read())

    def test_all_clear_exits_zero(self):
        with open(self.db, 'w') as f:
            f.write('"NickServ" {\n"alice" { "lastseen" "1"; };\n};\n')
        code, out, err = run_main(['--db', self.db, '--conf', self.conf], FakeKeycloak({'alice': [ALICE_UUID]}))
        self.assertEqual(code, 0, out + err)

    def test_flags_override_the_conf_and_the_secret_is_never_printed(self):
        secret_file = os.path.join(self.tmp, 'secret')
        with open(secret_file, 'w') as f:
            f.write('file-secret-do-not-print\n')
        keycloak = FakeKeycloak(fixture_users(), failing=('alice',))
        code, out, err = run_main(['--db', self.db, '--conf', self.conf, '--keycloak-url', 'http://kc.example:8080',
                                   '--realm', 'other', '--client-id', 'cid', '--client-secret-file', secret_file],
                                  keycloak)
        self.assertEqual(keycloak.settings, {'url': 'http://kc.example:8080', 'realm': 'other',
                                             'client_id': 'cid', 'secret': 'file-secret-do-not-print'})
        for text in (out, err):
            self.assertNotIn('do-not-print', text)
        code, out, err = run_main(['--db', self.db, '--conf', self.conf], FakeKeycloak(fixture_users()))
        self.assertNotIn('do-not-print', out + err)

    def test_profile_refused_uses_the_name_limits(self):
        code, out, err = run_main(['--db', self.db, '--conf', self.conf, '--name-min', '3', '--name-max', '4'],
                                  FakeKeycloak({}, profile=None))
        self.assertIn('length 3..4', out)
        self.assertIn('not from the realm', out)

    def test_a_db_that_does_not_parse_is_exit_1(self):
        with open(self.db, 'w') as f:
            f.write('"NickServ" {\n"alice" { "lastseen" "1" };\n};\n')
        code, out, err = run_main(['--db', self.db, '--conf', self.conf], FakeKeycloak({}))
        self.assertEqual(code, 1)
        self.assertIn('line 2', err)


    def test_replaced_id_is_exit_2_and_reported(self):
        with open(self.db, 'w') as f:
            f.write('"NickServ" {\n"alice" { "kc_id_prev" ("%s"); "lastseen" "1"; };\n};\n' % ALICE_ID)
        report_path = os.path.join(self.tmp, 'report.json')
        code, out, err = run_main(['--db', self.db, '--conf', self.conf, '--json', report_path],
                                  FakeKeycloak({'alice': [ALICE_UUID]}))
        self.assertEqual(code, 2, out + err)
        self.assertIn('alice: %s' % ALICE_ID, out)
        self.assertIn('an oper must REBIND it', out)
        self.assertIn('replaced id: 1', out)
        self.assertIn('bound now: 0', out)
        with open(report_path) as f:
            self.assertIn('"replaced_id": [', f.read())

    def out_run(self):
        target = os.path.join(self.tmp, 'x3.db.bound')
        code, out, err = run_main(['--db', self.db, '--conf', self.conf, '--out', target],
                                  FakeKeycloak(fixture_users()))
        return target, code, out, err

    def test_a_failed_write_leaves_no_out_file(self):
        with mock.patch.object(bki.os, 'fsync', side_effect=OSError(errno.ENOSPC, 'No space left on device')):
            target, code, out, err = self.out_run()
        self.assertEqual(code, 1)
        self.assertFalse(os.path.lexists(target))
        self.assertIn('No space left on device', err)
        self.assertIn('removed', err)
        self.assertEqual(read_fixture(self.db), read_fixture())

    def test_a_failed_verification_leaves_no_out_file(self):
        for failure in (bki.VerifyError('the new file differs'), RuntimeError('something unexpected')):
            with mock.patch.object(bki, 'verify_output', side_effect=failure):
                target, code, out, err = self.out_run()
            self.assertEqual(code, 1, failure)
            self.assertFalse(os.path.lexists(target), failure)
            self.assertIn(str(failure), err)
            self.assertNotIn('Traceback', err)

    def test_an_interrupt_removes_the_out_file_and_is_raised(self):
        with mock.patch.object(bki, 'verify_output', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.out_run()
        self.assertFalse(os.path.lexists(os.path.join(self.tmp, 'x3.db.bound')))

    def test_a_failed_removal_names_the_leftover_file(self):
        with mock.patch.object(bki.os, 'fsync', side_effect=OSError(errno.EIO, 'Input/output error')), \
                mock.patch.object(bki.os, 'unlink', side_effect=PermissionError(errno.EACCES, 'Permission denied')):
            target, code, out, err = self.out_run()
        self.assertEqual(code, 1)
        self.assertNotIn('Traceback', err)
        self.assertEqual(len(err.strip().splitlines()), 1)
        self.assertIn('could not remove the partial file %s' % target, err)

    def test_out_gets_the_input_owner_and_mode(self):
        os.chmod(self.db, 0o640)
        st = os.stat(self.db)
        with mock.patch.object(bki.os, 'chown') as chown:
            target, code, out, err = self.out_run()
        self.assertEqual(code, 2, err)
        chown.assert_called_once_with(target, st.st_uid, st.st_gid)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o640)
        self.assertNotIn('WARNING', err)

    def test_an_owner_that_cannot_be_given_is_a_warning(self):
        with mock.patch.object(bki.os, 'chown', side_effect=PermissionError(errno.EPERM, 'Operation not permitted')):
            target, code, out, err = self.out_run()
        self.assertEqual(code, 2, err)                      # finished, as without the warning
        self.assertTrue(os.path.exists(target))            # the file is kept
        self.assertIn('WARNING', err)
        self.assertIn('owner', err)
        self.assertIn(target, err)

    def test_json_refuses_an_existing_file(self):
        existing = os.path.join(self.tmp, 'report.json')
        with open(existing, 'w') as f:
            f.write('keep me')
        code, out, err = run_main(['--db', self.db, '--conf', self.conf, '--json', existing],
                                  FakeKeycloak(fixture_users()))
        self.assertEqual(code, 1)
        self.assertIn('--json', err)
        with open(existing) as f:
            self.assertEqual(f.read(), 'keep me')

    def test_report_text_names_the_no_user_level_and_the_new_lists(self):
        with open(self.db, 'w') as f:
            f.write('"NickServ" {\n"alice" { "kc_id" "%s"; };\n"bob" { "kc_id" "%s"; };\n'
                    '"oper1" { "opserv_level" "900"; };\n};\n' % (ALICE_ID, ALICE_ID))
        code, out, err = run_main(['--db', self.db, '--conf', self.conf], FakeKeycloak({'bob': [ALICE_UUID]}))
        self.assertEqual(code, 2, err)
        self.assertIn('oper1 (OpServ level 900;', out)
        self.assertIn('until an oper REBINDs', out)
        self.assertIn('alice: %s' % ALICE_ID, out)          # bound, no Keycloak user of that name
        self.assertIn('%s: alice, bob' % ALICE_ID, out)      # shared

    def test_a_file_that_was_already_there_is_never_removed(self):
        existing = os.path.join(self.tmp, 'exists.db')
        with open(existing, 'w') as f:
            f.write('keep me')
        problem = bki._write_new_file(existing, b'new', lambda: None)
        self.assertIn('exists', problem)
        with open(existing) as f:
            self.assertEqual(f.read(), 'keep me')


if __name__ == '__main__':
    unittest.main()
