#!/usr/bin/env python3
"""bind-keycloak-ids: give existing X3 accounts their Keycloak ids, offline.

Run it with X3 stopped, on a COPY of x3.db.  For every account ("handle")
that has no "kc_id" yet and exactly one Keycloak user of the same name
(under IRC case folding), it reports the binding; with --out it writes a new
file that is the input plus one "kc_id" entry per bound account, and checks
that new file before it keeps it.  The input is never written.

    tools/bind-keycloak-ids.py --db <copy of x3.db> --conf <x3.conf>
        [--keycloak-url U --realm R --client-id C --client-secret-file F]
        [--name-min 2 --name-max 30] [--out <new file>] [--json <report file>]

Exit codes: 0 finished, nothing needs a look; 2 finished, but some entries
need a look (errors, ambiguous, mismatched, replaced id, no Keycloak user,
bound with no Keycloak user of that name, shared id); 1 usage, parse or
verification failure.  See tools/README.bind-keycloak-ids.

The new file gets the input's owner and mode where the script may give
them; where it may not (not run as root), it says so: X3 must be able to
read and write the file it starts with.

Python 3 standard library only.  Files are read and written as bytes (via
Latin-1, one character per byte), so offsets are byte offsets and every byte
the script does not insert is written back as it was read.
"""

import argparse
import base64
import itertools
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass, field
from typing import NamedTuple, Optional

# ---------------------------------------------------------------------------
# The recdb syntax (src/recdb.c is the authority)
#
#   database   := record*
#   record     := qstring [ '=' ] ( qstring | object | stringlist ) ';'
#   object     := '{' record* '}'
#   stringlist := '(' [ qstring [',' qstring]* ] ')'
#
# plus C-locale isspace() whitespace and /* */ and // comments between tokens.
# ---------------------------------------------------------------------------

_SPACE = ' \t\n\v\f\r'
_HEX = '0123456789abcdefABCDEF'
_PLAIN_RUN = re.compile(r'[^"\\\n]*')
_NAMED_ESCAPES = {'a': '\a', 'b': '\b', 't': '\t', 'n': '\n', 'v': '\v',
                  'f': '\f', 'r': '\r', '\\': '\\', '"': '"'}


class ParseError(ValueError):
    """Something src/recdb.c would refuse (or never finish reading)."""

    def __init__(self, message, text, pos):
        pos = min(pos, len(text))
        self.line = text.count('\n', 0, pos) + 1
        self.column = pos - (text.rfind('\n', 0, pos) + 1) + 1
        self.reason = message
        super().__init__('%s at line %d column %d' % (message, self.line, self.column))


class Str:
    __slots__ = ('value',)

    def __init__(self, value):
        self.value = value


class List:
    __slots__ = ('items',)

    def __init__(self, items):
        self.items = items


class Obj:
    """An object: its records in file order (repeats kept), and the offset
    just after its opening '{' (None for the top level of a file)."""
    __slots__ = ('entries', 'offset')

    def __init__(self, offset):
        self.entries = []
        self.offset = offset

    def get(self, key):
        """The value X3 sees for key: matched under IRC folding, last one wins
        (dict_insert replaces an existing key)."""
        want = irc_fold(key)
        found = None
        for name, value in self.entries:
            if irc_fold(name) == want:
                found = value
        return found

    def get_path(self, path):
        node = self
        for part in path.split('/'):
            if not isinstance(node, Obj):
                return None
            node = node.get(part)
        return node


class _Reader:
    def __init__(self, text):
        self.text = text
        self.end = len(text)
        self.pos = 0

    def fail(self, message, pos=None):
        raise ParseError(message, self.text, self.pos if pos is None else pos)

    def skip(self):
        """parse_skip_ws: skip whitespace and comments; return the next
        character without consuming it, or None at the end of the text."""
        text, end = self.text, self.end
        while True:
            pos = self.pos
            while pos < end and text[pos] in _SPACE:
                pos += 1
            self.pos = pos
            if pos >= end:
                return None
            c = text[pos]
            if c != '/':
                return c
            d = text[pos + 1] if pos + 1 < end else None
            if d == '*':
                # recdb.c: scan to a '*', then the NEXT character must be '/';
                # if it is not, it is dropped (even a '*') and the scan goes on.
                scan = pos + 2
                while True:
                    star = text.find('*', scan)
                    if star < 0 or star + 1 >= end:
                        # recdb.c loops forever here; X3 would never start.
                        self.fail('Unterminated /* comment (X3 would never finish reading this)', pos)
                    if text[star + 1] == '/':
                        self.pos = star + 2
                        break
                    scan = star + 2
            elif d == '/':
                newline = text.find('\n', pos + 2)
                self.pos = end if newline < 0 else newline
            else:
                return '/'

    def qstring(self):
        """parse_qstring, with the opening '"' at self.pos."""
        text, end = self.text, self.end
        start = self.pos
        pos = start + 1
        out = []
        while True:
            run = _PLAIN_RUN.match(text, pos)
            out.append(run.group())
            pos = run.end()
            if pos >= end:
                self.fail('Unterminated string', start)
            c = text[pos]
            pos += 1
            if c == '"':
                break
            if c == '\n':
                self.fail('Unterminated string', pos - 1)
            # a backslash
            if pos >= end:
                self.fail('Unterminated string', start)
            e = text[pos]
            pos += 1
            if '0' <= e <= '7':
                digits = e
                for i in (1, 2):
                    if i == 2 and digits[0] > '3':
                        break
                    if pos >= end or not '0' <= text[pos] <= '7':
                        break
                    digits += text[pos]
                    pos += 1
                out.append(chr(int(digits, 8)))
            elif e == 'x':
                digits = ''
                while len(digits) < 2 and pos < end and text[pos] in _HEX:
                    digits += text[pos]
                    pos += 1
                out.append(chr(int(digits, 16)) if digits else '\\x')
            elif e in _NAMED_ESCAPES:
                out.append(_NAMED_ESCAPES[e])
            else:
                out.append('\\' + e)
        self.pos = pos
        value = ''.join(out)
        nul = value.find('\0')
        return value if nul < 0 else value[:nul]   # X3 keeps a C string

    def record(self, target):
        """parse_record_int into target; False at a clean end of text."""
        c = self.skip()
        if c is None:
            return False
        if c != '"':
            self.fail('Expected \'"\'', self.pos + 1)
        name = self.qstring()
        c = self.skip()
        if c is None:
            self.fail('Expected record data')
        if c == '=':
            self.pos += 1
            c = self.skip()
        if c == '"':
            value = Str(self.qstring())
        elif c == '{':
            value = self.object()
        elif c == '(':
            value = self.string_list()
        else:
            self.fail('Expected start of some record data', self.pos + 1)
        if self.skip() != ';':
            self.fail("Expected ';'", self.pos + 1)
        self.pos += 1
        target.entries.append((name, value))
        return True

    def object(self):
        opened = self.pos
        self.pos += 1
        obj = Obj(self.pos)
        while True:
            c = self.skip()
            if c == '}':
                self.pos += 1
                return obj
            if c is None:
                self.fail("Expected ';': the object opened here is never closed", opened)
            self.record(obj)

    def string_list(self):
        opened = self.pos
        self.pos += 1
        items = []
        while True:
            c = self.skip()
            if c is None:
                self.fail("Expected ';': the list opened here is never closed", opened)
            if c == ')':
                self.pos += 1
                return List(items)
            if c != '"':
                self.fail('Expected \'"\'', self.pos + 1)
            items.append(self.qstring())
            c = self.skip()
            if c is None:
                self.fail("Expected ';': the list opened here is never closed", opened)
            if c == ')':
                self.pos += 1
                return List(items)
            if c != ',':
                self.fail("Expected ','", self.pos + 1)
            self.pos += 1


def parse(text):
    """Read recdb text (x3.db or x3.conf) into an Obj; ParseError on anything
    recdb.c would refuse."""
    reader = _Reader(text)
    root = Obj(None)
    while reader.record(root):
        pass
    return root


def _plain(node, extra=None):
    """A comparable form of a tree; extra maps id(Obj) -> kc_id to put first."""
    if isinstance(node, Str):
        return ('s', node.value)
    if isinstance(node, List):
        return ('l', tuple(node.items))
    entries = [(k, _plain(v, extra)) for k, v in node.entries]
    if extra and id(node) in extra:
        entries.insert(0, ('kc_id', ('s', extra[id(node)])))
    return ('o', tuple(entries))


# ---------------------------------------------------------------------------
# Names and ids
# ---------------------------------------------------------------------------

_FOLD = {c: c + 32 for c in range(ord('A'), ord('Z') + 1)}
_FOLD.update({ord('['): ord('{'), ord('\\'): ord('|'), ord(']'): ord('}'), ord('^'): ord('~')})
_FOLD.update({c: c + 32 for c in range(0xC0, 0xD7)})   # tools_init, P10 build
_FOLD.update({c: c + 32 for c in range(0xD8, 0xDF)})


def irc_fold(name):
    """X3's case folding (tools_init's irc_tolower table): A-Z, [\\]^ -> {|}~,
    and the Latin-1 capitals.  Names are byte strings read as Latin-1."""
    return name.translate(_FOLD)


_COMPACT_ID = re.compile(r'[A-Za-z0-9_-]{22}')


def compact_id(uuid):
    """X3's kcid_from_uuid: a UUID (dashes anywhere, 32 hex digits) as 22
    unpadded base64url characters.  ValueError for anything else."""
    if not isinstance(uuid, str):
        raise ValueError('not a UUID: %r' % (uuid,))
    digits = uuid.replace('-', '')
    if len(digits) != 32 or any(c not in _HEX for c in digits):
        raise ValueError('not a UUID: %r' % (uuid,))
    return base64.urlsafe_b64encode(bytes.fromhex(digits)).decode('ascii').rstrip('=')


def _normal_id(stored):
    if _COMPACT_ID.fullmatch(stored):
        return stored
    try:
        return compact_id(stored)
    except ValueError:
        return stored


def _as_text(name):
    """A byte-string name as the Unicode text Keycloak would see, or None when
    its bytes are not UTF-8."""
    try:
        return name.encode('latin-1').decode('utf-8')
    except (UnicodeEncodeError, UnicodeDecodeError):
        return None


def _from_text(text):
    return text.encode('utf-8').decode('latin-1')


def _shown(name):
    text = _as_text(name)
    if text is None:
        text = name
    return text if text.isprintable() else repr(text)


# ---------------------------------------------------------------------------
# X3's account-name rule (nickserv_conf_read, valid_handle)
# ---------------------------------------------------------------------------

NICKSERV_VALID_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'


class NameRuleError(ValueError):
    pass


_INTERVAL = re.compile(r'\{[0-9]+(,[0-9]*)?\}')


def _posix_ere(source, pattern):
    """Compile a POSIX extended regex (REG_EXTENDED|REG_ICASE) with Python's
    re, refusing anything re would not read the same way."""
    def refuse(why):
        raise NameRuleError('%s "%s": Python cannot read this pattern the way X3 does (%s); '
                            'check the names by hand or simplify the pattern' % (source, pattern, why))

    i, n = 0, len(pattern)
    atom = False            # the last token can take a quantifier
    while i < n:
        c = pattern[i]
        if c == '\\':
            if i + 1 >= n:
                refuse('it ends in a backslash')
            if pattern[i + 1].isalnum():
                refuse('the escape \\%s' % pattern[i + 1])
            i += 2
            atom = True
        elif c == '[':
            j = i + 1
            if j < n and pattern[j] == '^':
                j += 1
            if j < n and pattern[j] == ']':
                j += 1
            while j < n and pattern[j] != ']':
                if pattern[j] == '[' and j + 1 < n and pattern[j + 1] in ':.=':
                    refuse('a POSIX class or collating element in a bracket expression')
                if pattern[j] == '\\':
                    refuse('a backslash in a bracket expression')
                j += 1
            if j >= n:
                refuse('an unclosed bracket expression')
            i = j + 1
            atom = True
        elif c in '*+?' or c == '{':
            if c == '{':
                m = _INTERVAL.match(pattern, i)
                if not m:
                    refuse('a "{" that is not an interval')
                stop = m.end()
            else:
                stop = i + 1
            if not atom:
                refuse('a repetition with nothing before it, or two in a row')
            i = stop
            atom = False
        elif c == '(':
            if pattern.startswith('(?', i):
                refuse('a "(?" group')
            i += 1
            atom = False
        elif c in '|^$':
            i += 1
            atom = False
        else:
            i += 1
            atom = True
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            return re.compile(pattern, re.IGNORECASE | re.ASCII | re.DOTALL)
    except (re.error, Warning) as exc:
        refuse(str(exc))


@dataclass
class NameRule:
    source: str                 # 'valid_handle_regex', 'valid_account_regex' or 'none'
    pattern: Optional[str]
    regex: object = None

    def test(self, name):
        if self.regex is not None:
            return self.regex.search(name) is not None     # regexec: a search, not anchored
        return all(c in NICKSERV_VALID_CHARS for c in name)

    def describe(self):
        if self.source == 'none':
            return 'none set in x3.conf: X3\'s built-in characters (%s)' % NICKSERV_VALID_CHARS
        return '%s "%s" (from x3.conf)' % (self.source, self.pattern)


def read_name_rule(conf):
    """The rule nickserv_conf_read installs: services/nickserv's
    valid_handle_regex, else its valid_account_regex, else the built-in
    character set."""
    node = conf.get_path('services/nickserv')
    if isinstance(node, Obj):
        for key in ('valid_handle_regex', 'valid_account_regex'):
            value = node.get(key)
            if isinstance(value, Str):
                return NameRule(key, value.value, _posix_ere(key, value.value))
    return NameRule('none', None, None)


# ---------------------------------------------------------------------------
# Keycloak's username rules
# ---------------------------------------------------------------------------

# Keycloak's username-prohibited-characters list (built into Keycloak; the
# user profile names the validator but not its characters).  Measured on
# Keycloak 26.4.7: these, whitespace and control characters are refused;
# - _ . @ + are accepted.
KEYCLOAK_PROHIBITED = set('<>&"\'$%!#?§,;:*~/\\|^=[]{}()`')


@dataclass
class UsernameRules:
    source: str                         # 'realm' or 'default'
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    patterns: list = field(default_factory=list)    # [(text, compiled)]
    prohibited: bool = False
    unchecked: list = field(default_factory=list)

    def describe(self):
        parts = []
        if self.min_length is not None or self.max_length is not None:
            parts.append('length %s..%s' % ('' if self.min_length is None else self.min_length,
                                            '' if self.max_length is None else self.max_length))
        for text, _ in self.patterns:
            parts.append('pattern "%s"' % text)
        if self.prohibited:
            parts.append("Keycloak's prohibited characters")
        what = ', '.join(parts) or 'none'
        if self.source == 'realm':
            what = 'from the realm: ' + what
        else:
            what = ('not from the realm (its user profile could not be read), so --name-min/--name-max '
                    'and the built-in list: ' + what)
        if self.unchecked:
            what += '; not checked by this script: ' + ', '.join(self.unchecked)
        return what


class RequestRefused(Exception):
    """Keycloak answered a request with an HTTP error."""

    def __init__(self, what, status):
        self.what = what
        self.status = status
        super().__init__('%s refused: HTTP %s' % (what, status))


class KeycloakUnreachable(Exception):
    pass


def _number(value):
    if value is None or value == '':
        return None
    return int(value)


def realm_username_rules(get_profile):
    """Keycloak's rules for usernames, from the realm's user profile
    (GET /admin/realms/{realm}/users/profile, fetched by get_profile()).
    None when that request is refused."""
    try:
        profile = get_profile()
    except RequestRefused:
        return None
    attributes = profile.get('attributes') if isinstance(profile, dict) else None
    if not isinstance(attributes, list):
        raise ValueError('the realm\'s user profile has no "attributes" list')
    username = next((a for a in attributes if isinstance(a, dict) and a.get('name') == 'username'), {})
    rules = UsernameRules('realm')
    for name, config in (username.get('validations') or {}).items():
        config = config if isinstance(config, dict) else {}
        if name == 'length':
            rules.min_length = _number(config.get('min'))
            rules.max_length = _number(config.get('max'))
        elif name == 'pattern':
            text = config.get('pattern')
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter('error')
                    rules.patterns.append((text, re.compile(text)))
            except (re.error, Warning, TypeError):
                rules.unchecked.append('pattern "%s" (Python cannot read it as Keycloak does)' % (text,))
        elif name == 'username-prohibited-characters':
            rules.prohibited = True
        else:
            rules.unchecked.append(name)
    return rules


def default_username_rules(name_min=2, name_max=30):
    return UsernameRules('default', name_min, name_max, [], True, [])


def keycloak_allows(name, rules):
    """True when Keycloak would accept name as a username under rules."""
    text = _as_text(name)
    if text is None:
        return False
    length = len(text.encode('utf-16-le')) // 2          # Java's String.length()
    if rules.min_length is not None and length < rules.min_length:
        return False
    if rules.max_length is not None and length > rules.max_length:
        return False
    for _, regex in rules.patterns:
        if not regex.fullmatch(text):                     # PatternValidator: matcher.matches()
            return False
    if rules.prohibited:
        for c in text:
            if c in KEYCLOAK_PROHIBITED or c.isspace() or unicodedata.category(c) == 'Cc':
                return False
    return True


# ---------------------------------------------------------------------------
# Binding
# ---------------------------------------------------------------------------

class NoUser(NamedTuple):
    handle: str
    name_allowed: bool
    matches_rule: Optional[bool]
    opserv_level: int = 0


class BoundNoUser(NamedTuple):
    handle: str
    stored: str


class SharedId(NamedTuple):
    id: str
    handles: list


class Mismatch(NamedTuple):
    handle: str
    stored: str
    keycloak: str


class Ambiguous(NamedTuple):
    handle: str
    ids: list


class Failure(NamedTuple):
    handle: str
    error: str


class Replaced(NamedTuple):
    handle: str
    id: str


@dataclass
class Report:
    handles_total: int = 0
    bound: dict = field(default_factory=dict)
    already_bound: int = 0
    mismatched: list = field(default_factory=list)
    no_user: list = field(default_factory=list)
    ambiguous: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    replaced_id: list = field(default_factory=list)
    bound_no_user: list = field(default_factory=list)
    shared_id: list = field(default_factory=list)
    name_rule: Optional[tuple] = None
    outside_name_rule: list = field(default_factory=list)
    rules_source: str = 'default'
    unchecked_validators: list = field(default_factory=list)
    name_rule_text: str = ''
    rules_text: str = ''

    def needs_a_look(self):
        return bool(self.errors or self.ambiguous or self.mismatched or self.no_user or self.replaced_id
                    or self.bound_no_user or self.shared_id)


class InputError(ValueError):
    pass


def nickserv_section(conf):
    """Where saxdb keeps NickServ: dbs/NickServ's mondo_section, or None when
    x3.conf gives NickServ a file of its own (then the handles are that
    file's top level)."""
    node = conf.get_path('dbs/NickServ')
    if isinstance(node, Obj):
        value = node.get('mondo_section')
        if isinstance(value, Str):
            return value.value
    return None


def _handles(db, section):
    if section is None:
        return db
    node = db.get(section)
    if not isinstance(node, Obj):
        raise InputError('the file has no "%s" section (x3.conf\'s dbs/NickServ/mondo_section)' % section)
    return node


def _groups(handles):
    groups = {}
    for name, node in handles.entries:
        groups.setdefault(irc_fold(name), []).append((name, node))
    return groups


def _kc_entry(node):
    """(present, value): X3 reads the last "kc_id", and only as a string."""
    values = [v for k, v in node.entries if irc_fold(k) == 'kc_id']
    return (bool(values), values[-1] if values else None)


def _opserv_level(node):
    """The account's OpServ level as X3 reads it (strtoul; 0 when absent or
    not a number)."""
    values = [v for k, v in node.entries if irc_fold(k) == 'opserv_level']
    if not values or not isinstance(values[-1], Str):
        return 0
    m = re.match(r'\s*\+?(\d+)', values[-1].value)
    return int(m.group(1)) if m else 0


def _replaced_ids(node):
    """(present, ids): the ids this account's binding replaced ("kc_id_prev").
    X3 reads the last such key, as a string list (newest first) or, as a
    single-id X3 wrote it, one string; ids is None when it is neither."""
    values = [v for k, v in node.entries if irc_fold(k) == 'kc_id_prev']
    if not values:
        return (False, [])
    value = values[-1]
    if isinstance(value, List):
        return (True, list(value.items))
    if isinstance(value, Str):
        return (True, [value.value])
    return (True, None)


MAX_FAILURES_IN_A_ROW = 5


def bind(db, lookup, rule, rules, section='NickServ'):
    """Decide, per account, what to do; changes nothing.  lookup(name) returns
    Keycloak's users of that name as [{'id', 'username'}]."""
    handles = _handles(db, section)
    groups = _groups(handles)
    report = Report(rules_source=rules.source, unchecked_validators=list(rules.unchecked),
                    rules_text=rules.describe())
    if rule is not None:
        report.name_rule = (rule.source, rule.pattern)
        report.name_rule_text = rule.describe()

    stored_by_id = {}
    holders = {}
    for items in groups.values():
        name, node = items[-1]
        if isinstance(node, Obj):
            present, value = _kc_entry(node)
            if isinstance(value, Str):
                stored_by_id.setdefault(_normal_id(value.value), name)
                holders.setdefault(_normal_id(value.value), []).append(name)
    # Two handles holding one Keycloak user: X3 keeps that user while either
    # holds it (an unregister of one does not delete it), and a login as it
    # binds whichever handle has its name.  Decide which handle it belongs to.
    report.shared_id = [SharedId(i, names) for i, names in holders.items() if len(names) > 1]

    failures_in_a_row = 0
    for fold, items in groups.items():
        name, node = items[-1]
        report.handles_total += 1
        if rule is not None and not rule.test(name):
            report.outside_name_rule.append(name)
        if len(items) > 1:
            report.errors.append(Failure(name, 'the file holds this account %d times (X3 keeps only the last)'
                                         % len(items)))
            continue
        if not isinstance(node, Obj):
            report.errors.append(Failure(name, 'not an object; X3 cannot read this account'))
            continue
        present, stored = _kc_entry(node)
        if present and not isinstance(stored, Str):
            report.errors.append(Failure(name, 'its "kc_id" is not a string'))
            continue
        _, replaced = _replaced_ids(node)
        if replaced is None:
            report.errors.append(Failure(name, 'its "kc_id_prev" is neither a string nor a list of strings'))
            continue
        if failures_in_a_row >= MAX_FAILURES_IN_A_ROW:
            report.errors.append(Failure(name, 'not looked up: Keycloak failed %d requests in a row'
                                         % MAX_FAILURES_IN_A_ROW))
            continue
        try:
            users = lookup(name)
            failures_in_a_row = 0
        except NotLookedUp as exc:      # refused before any request: not a Keycloak failure
            report.errors.append(Failure(name, str(exc)))
            continue
        except Exception as exc:        # any failure leaves the account as it is
            failures_in_a_row += 1
            report.errors.append(Failure(name, 'Keycloak lookup failed: %s' % exc))
            continue
        try:
            ids = [compact_id(u['id']) for u in users if irc_fold(u['username']) == fold]
        except (KeyError, TypeError, ValueError) as exc:
            report.errors.append(Failure(name, 'Keycloak answered with a user this script cannot read: %s' % exc))
            continue

        if present:
            if not ids:
                # Keycloak has no user of that name any more: deleted, or
                # renamed (X3 then refuses its logins under the new name).
                report.bound_no_user.append(BoundNoUser(name, stored.value))
            elif len(ids) > 1:
                report.ambiguous.append(Ambiguous(name, ids))
            elif ids[0] == _normal_id(stored.value):
                report.already_bound += 1
            else:
                report.mismatched.append(Mismatch(name, stored.value, ids[0]))
            continue
        if not ids:
            report.no_user.append(NoUser(name, keycloak_allows(name, rules),
                                         None if rule is None else rule.test(name),
                                         _opserv_level(node)))
        elif len(ids) > 1:
            report.ambiguous.append(Ambiguous(name, ids))
        elif ids[0] in {_normal_id(r) for r in replaced}:
            # REBIND * moved this id into kc_id_prev on purpose; X3 refuses it
            # as the account's id ("a replaced id is never the current one").
            report.replaced_id.append(Replaced(name, ids[0]))
        elif ids[0] in stored_by_id:
            report.errors.append(Failure(name, 'Keycloak user %s is already bound to account %s'
                                         % (ids[0], _shown(stored_by_id[ids[0]]))))
        else:
            report.bound[name] = ids[0]
            stored_by_id[ids[0]] = name
    return report


# ---------------------------------------------------------------------------
# Writing and checking the new file
# ---------------------------------------------------------------------------

_LINE_END = re.compile(r'[ \t]*(\r?\n)')
_INDENT = re.compile(r'[ \t]*')


class VerifyError(Exception):
    pass


def _insertion(text, offset, kc_id):
    entry = '"kc_id" "%s";' % kc_id
    end = _LINE_END.match(text, offset)
    if not end:
        # X3 writes an account on one line: "name" { "k" "v"; ... };
        return ' ' + entry
    # A "{" that ends its line: the entry gets a line of its own.
    after = end.end()
    indent = _INDENT.match(text, after).group()
    if text.startswith('}', after + len(indent)):
        indent += '\t'
    return end.group(1) + indent + entry


def write_bound(text, db, bound, section='NickServ'):
    """text with one "kc_id" entry inserted just after the opening "{" of each
    bound account, and nothing else changed (no re-serialization)."""
    groups = _groups(_handles(db, section))
    inserts = []
    for name, kc_id in bound.items():
        if not _COMPACT_ID.fullmatch(kc_id):
            raise ValueError('not a compact Keycloak id: %r' % (kc_id,))
        items = groups.get(irc_fold(name))
        node = items[-1][1] if items else None
        if not isinstance(node, Obj) or node.offset is None or text[node.offset - 1] != '{':
            raise ValueError('no account object for %r in the text' % (name,))
        inserts.append((node.offset, _insertion(text, node.offset, kc_id)))
    inserts.sort()
    pieces, last = [], 0
    for offset, piece in inserts:
        pieces.append(text[last:offset])
        pieces.append(piece)
        last = offset
    pieces.append(text[last:])
    return ''.join(pieces)


def verify_output(db, out_text, bound, section='NickServ'):
    """The new text must parse, and its tree must equal the input's tree plus
    exactly one leading "kc_id" entry in each bound account."""
    try:
        out_db = parse(out_text)
    except ParseError as exc:
        raise VerifyError('the new file does not parse: %s' % exc)
    groups = _groups(_handles(db, section))
    extra = {}
    for name, kc_id in bound.items():
        extra[id(groups[irc_fold(name)][-1][1])] = kc_id
    expected = _plain(db, extra)
    actual = _plain(out_db)
    if expected != actual:
        where = 'the file'
        for (want, got) in zip(expected[1], actual[1]):
            if want != got:
                where = 'the "%s" section' % _shown(want[0])
                break
        else:
            if len(expected[1]) != len(actual[1]):
                where = 'the number of top-level sections'
        raise VerifyError('the new file differs from the input plus the kc_id entries (first in %s)' % where)


# ---------------------------------------------------------------------------
# Keycloak
# ---------------------------------------------------------------------------

def keycloak_settings(conf):
    """keycloak_url, keycloak_realm, keycloak_client_id and
    keycloak_client_secret from x3.conf's services/nickserv block."""
    node = conf.get_path('services/nickserv')
    settings = {}
    for key, conf_key in (('url', 'keycloak_url'), ('realm', 'keycloak_realm'),
                          ('client_id', 'keycloak_client_id'), ('secret', 'keycloak_client_secret')):
        value = node.get(conf_key) if isinstance(node, Obj) else None
        settings[key] = value.value if isinstance(value, Str) and value.value else None
    return settings


class KeycloakClient:
    """Client-credentials grant and the two admin reads this script needs;
    urllib only.  The token is renewed before it expires."""

    def __init__(self, settings, timeout=15):
        self.base = settings['url'].rstrip('/')
        self.realm = urllib.parse.quote(settings['realm'], safe='')
        self.client_id = settings['client_id']
        self._secret = settings['secret']
        self.timeout = timeout
        self._token = None
        self._renew_at = 0.0

    def __repr__(self):
        return '<KeycloakClient %s realm %s client %s>' % (self.base, self.realm, self.client_id)

    def _open(self, request, what):
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise RequestRefused(what, exc.code) from None
        except (urllib.error.URLError, OSError) as exc:
            raise KeycloakUnreachable('%s: %s' % (what, getattr(exc, 'reason', exc))) from None
        try:
            return json.loads(raw.decode('utf-8'))
        except ValueError:
            raise KeycloakUnreachable('%s: the answer is not JSON' % what) from None

    def _bearer(self, renew=False):
        if renew or self._token is None or time.monotonic() >= self._renew_at:
            body = urllib.parse.urlencode({'grant_type': 'client_credentials', 'client_id': self.client_id,
                                           'client_secret': self._secret}).encode('ascii')
            request = urllib.request.Request(
                '%s/realms/%s/protocol/openid-connect/token' % (self.base, self.realm), data=body,
                headers={'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'})
            answer = self._open(request, 'token request')
            token = answer.get('access_token') if isinstance(answer, dict) else None
            if not token:
                raise RequestRefused('token request', 'no access_token in the answer')
            lifetime = float(answer.get('expires_in') or 60)
            self._token = token
            self._renew_at = time.monotonic() + max(lifetime - 30, lifetime / 2)
        return self._token

    def check(self):
        """Get a token now, so bad settings fail before any account is looked at."""
        self._bearer(renew=True)

    def _get(self, path, query=''):
        url = '%s/admin/realms/%s%s%s' % (self.base, self.realm, path, '?' + query if query else '')
        for attempt in (0, 1):
            request = urllib.request.Request(url, headers={
                'Authorization': 'Bearer ' + self._bearer(renew=attempt == 1), 'Accept': 'application/json'})
            try:
                return self._open(request, 'GET ' + path)
            except RequestRefused as exc:
                if exc.status != 401 or attempt == 1:
                    raise
        raise AssertionError('not reached')

    def profile(self):
        return self._get('/users/profile')

    def lookup(self, name):
        """Every Keycloak user whose username equals name under irc_fold.
        Keycloak's exact search ignores letter case but not IRC folding, so
        each spelling of the bracket characters is asked for, and the
        answers are merged by user id."""
        found, without_id = {}, []
        for spelling in fold_spellings(name):
            query = 'username=%s&exact=true&briefRepresentation=true' % urllib.parse.quote(
                spelling.encode('latin-1'), safe='')
            users = self._get('/users', query)
            if not isinstance(users, list):
                raise ValueError('the user search did not answer with a list')
            for u in users:
                user = {'id': u.get('id'), 'username': _from_text(u.get('username') or '')}
                if user['id'] is None:
                    without_id.append(user)
                else:
                    found.setdefault(user['id'], user)
        return list(found.values()) + without_id


class NotLookedUp(Exception):
    """A name the lookup refuses to ask Keycloak about; nothing was sent."""


_FOLD_PAIRS = {'[': '[{', '{': '[{', ']': ']}', '}': ']}', '\\': '\\|', '|': '\\|', '^': '^~', '~': '^~'}
MAX_FOLD_CHARACTERS = 6         # 2**6 = 64 requests for one name


def fold_spellings(name):
    """Every spelling of name that irc_fold makes equal to it, as far as
    Keycloak cannot tell them apart itself: each of [ ] \\ ^ { } | ~ has two
    spellings (letters need none: Keycloak ignores their case)."""
    choices = [_FOLD_PAIRS.get(c, c) for c in name]
    count = sum(1 for c in name if c in _FOLD_PAIRS)
    if count > MAX_FOLD_CHARACTERS:
        raise NotLookedUp('not looked up: the name has %d of the characters [ ] \\ ^ { } | ~, and more than %d '
                          'would take over %d requests' % (count, MAX_FOLD_CHARACTERS, 2 ** MAX_FOLD_CHARACTERS))
    return [''.join(p) for p in itertools.product(*choices)]


def keycloak_lookup(url, realm, client_id, secret):
    """The real lookup(name): Keycloak's users whose username is name."""
    return KeycloakClient({'url': url, 'realm': realm, 'client_id': client_id, 'secret': secret}).lookup


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

class UsageError(Exception):
    pass


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        raise UsageError(message)


def _arguments(argv):
    parser = _ArgumentParser(
        prog='bind-keycloak-ids.py',
        description='Give existing X3 accounts their Keycloak ids. Run with X3 stopped, on a COPY of x3.db.')
    parser.add_argument('--db', required=True, help='a copy of x3.db (read only)')
    parser.add_argument('--conf', required=True, help="X3's x3.conf (read only)")
    parser.add_argument('--keycloak-url', help='overrides keycloak_url in x3.conf')
    parser.add_argument('--realm', help='overrides keycloak_realm')
    parser.add_argument('--client-id', help='overrides keycloak_client_id')
    parser.add_argument('--client-secret-file', help='a file holding the client secret (overrides '
                        'keycloak_client_secret; the secret is never taken from the command line)')
    parser.add_argument('--name-min', type=int, default=2, help="shortest username, when the realm's "
                        'user profile cannot be read (default 2)')
    parser.add_argument('--name-max', type=int, default=30, help='longest username, likewise (default 30)')
    parser.add_argument('--out', help='write the bound copy to this NEW file (it must not exist)')
    parser.add_argument('--json', help='also write the report as JSON to this NEW file (it must not exist)')
    return parser.parse_args(argv)


def _same_file(a, b):
    if os.path.exists(a) and os.path.exists(b):
        return os.path.samefile(a, b)
    return os.path.realpath(a) == os.path.realpath(b)


def _read(path):
    with open(path, 'rb') as f:
        return f.read()


def _report_text(report, db_path, settings, section):
    lines = ['bind-keycloak-ids: %s' % db_path,
             'Keycloak: %s, realm %s, client %s' % (settings['url'], settings['realm'], settings['client_id']),
             'accounts read from: %s' % ('section "%s"' % section if section is not None
                                         else 'the top level (x3.conf gives NickServ its own file)'),
             '']

    def block(title, entries):
        lines.append('%s (%d):' % (title, len(entries)))
        lines.extend('  ' + e for e in entries)
        lines.append('')

    block('Mismatched: the stored kc_id is not the id of Keycloak\'s user of that name; left as it is',
          ['%s: stored %s, Keycloak %s' % (_shown(m.handle), m.stored, m.keycloak) for m in report.mismatched])
    block('Replaced id: this handle was detached from that Keycloak user on purpose (REBIND *); '
          'an oper must REBIND it; left as it is',
          ['%s: %s (in its kc_id_prev)' % (_shown(r.handle), r.id) for r in report.replaced_id])
    block('Ambiguous: more than one Keycloak user of that name; left as it is',
          ['%s: %s' % (_shown(a.handle), ', '.join(a.ids)) for a in report.ambiguous])
    block('Errors: left as it is',
          ['%s: %s' % (_shown(e.handle), e.error) for e in report.errors])

    block('Bound, but Keycloak has no user of that name (deleted or renamed?); left as it is',
          ['%s: %s' % (_shown(b.handle), b.stored) for b in report.bound_no_user])
    block('Shared id: one Keycloak user is the kc_id of several accounts; decide which it belongs to '
          '(REBIND the others)',
          ['%s: %s' % (sh.id, ', '.join(_shown(h) for h in sh.handles)) for sh in report.shared_id])

    def no_user_line(n):
        notes = ['OpServ level %d' % n.opserv_level] if n.opserv_level else []
        notes.append('Keycloak would accept the name' if n.name_allowed else 'Keycloak would refuse the name')
        if n.matches_rule is False:
            notes.append('outside the current name rule')
        return '%s (%s)' % (_shown(n.handle), '; '.join(notes))
    # Opers first: those are the accounts whose loss of login matters most.
    no_user = sorted(report.no_user, key=lambda n: -n.opserv_level)
    block('No Keycloak user: cannot log in through Keycloak until an oper REBINDs it to its user; '
          'left as it is', [no_user_line(n) for n in no_user])
    block('Outside the current name rule', [_shown(h) for h in report.outside_name_rule])

    refused = sum(1 for n in report.no_user if not n.name_allowed)
    lines += ['Summary',
              '  handles total: %d' % report.handles_total,
              '  bound now: %d' % len(report.bound),
              '  already bound: %d' % report.already_bound,
              '  bound, no Keycloak user of that name: %d' % len(report.bound_no_user),
              '  shared id: %d' % len(report.shared_id),
              '  mismatched: %d' % len(report.mismatched),
              '  replaced id: %d (detached from that Keycloak user on purpose; an oper must REBIND it)'
              % len(report.replaced_id),
              '  ambiguous: %d' % len(report.ambiguous),
              '  errors: %d' % len(report.errors),
              '  no Keycloak user: %d (name not acceptable to Keycloak: %d / name acceptable: %d; '
              'with an OpServ level: %d)'
              % (len(report.no_user), refused, len(report.no_user) - refused,
                 sum(1 for n in report.no_user if n.opserv_level)),
              '  outside the current name rule: %d' % len(report.outside_name_rule),
              '  name rule: %s' % (report.name_rule_text or 'not checked'),
              '  Keycloak username rules: %s' % report.rules_text]
    return '\n'.join(lines)


def _report_json(report):
    show = lambda name: _as_text(name) if _as_text(name) is not None else name
    return {
        'handles_total': report.handles_total,
        'bound': {show(h): i for h, i in report.bound.items()},
        'already_bound': report.already_bound,
        'mismatched': [{'handle': show(m.handle), 'stored': m.stored, 'keycloak': m.keycloak}
                       for m in report.mismatched],
        'no_user': [{'handle': show(n.handle), 'name_allowed': n.name_allowed, 'matches_rule': n.matches_rule,
                     'opserv_level': n.opserv_level}
                    for n in report.no_user],
        'bound_no_user': [{'handle': show(b.handle), 'stored': b.stored} for b in report.bound_no_user],
        'shared_id': [{'id': sh.id, 'handles': [show(h) for h in sh.handles]} for sh in report.shared_id],
        'ambiguous': [{'handle': show(a.handle), 'ids': a.ids} for a in report.ambiguous],
        'replaced_id': [{'handle': show(r.handle), 'id': r.id} for r in report.replaced_id],
        'errors': [{'handle': show(e.handle), 'error': e.error} for e in report.errors],
        'name_rule': None if report.name_rule is None else
        {'source': report.name_rule[0], 'pattern': report.name_rule[1]},
        'outside_name_rule': [show(h) for h in report.outside_name_rule],
        'rules_source': report.rules_source,
        'unchecked_validators': report.unchecked_validators,
        'username_rules': report.rules_text,
    }


def _write_new_file(path, data, check):
    """Create path (it must not exist yet), write data, fsync, then check().
    On any failure, or an interrupt, the file this call created is removed
    (a file that was already there is never touched).  Returns None, or a
    one-line message; an interrupt is re-raised after the cleanup."""
    created = False
    stage = 'writing'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        stage = 'verification'
        check()
        return None
    except BaseException as exc:
        cleanup = ''
        if created:
            try:
                os.unlink(path)
                cleanup = '; %s removed' % path
            except OSError as unlink_error:
                cleanup = ('; could not remove the partial file %s (%s): delete it by hand'
                           % (path, unlink_error.strerror or unlink_error))
        if not isinstance(exc, Exception):
            if cleanup:
                print('bind-keycloak-ids: interrupted%s' % cleanup, file=sys.stderr)
            raise
        if not created:
            return '--out: %s' % exc
        return '--out: %s failed: %s%s' % (stage, exc, cleanup)


def _keep_owner_and_mode(path, like):
    """Give path the owner, group and mode of like.  X3 reads and rewrites
    the file it starts with; one it cannot open makes it start with no
    accounts at all.  Where that cannot be done (not run as root), a
    WARNING says what to fix before X3 starts; the file is kept."""
    st = os.stat(like)
    try:
        os.chmod(path, st.st_mode & 0o777)
    except OSError as exc:
        print('bind-keycloak-ids: WARNING: could not give %s the mode of %s (%o): %s; fix it before X3 starts'
              % (path, like, st.st_mode & 0o777, exc.strerror or exc), file=sys.stderr)
    try:
        os.chown(path, st.st_uid, st.st_gid)
    except OSError as exc:
        print('bind-keycloak-ids: WARNING: could not give %s the owner of %s (uid %d, gid %d): %s.  '
              'Its owner differs from the input\'s: give it the owner X3 runs as before X3 starts '
              '(as root: chown %d:%d %s), or X3 cannot read it and starts with no accounts.'
              % (path, like, st.st_uid, st.st_gid, exc.strerror or exc, st.st_uid, st.st_gid, path),
              file=sys.stderr)


def _fail(message):
    print('bind-keycloak-ids: %s' % message, file=sys.stderr)
    return 1


def main(argv=None, connect=None):
    try:
        args = _arguments(argv)
    except UsageError as exc:
        return _fail(str(exc))

    # Paths first: nothing is read or asked before the outputs are known to be safe.
    if args.out is not None:
        for other, flag in ((args.db, '--db'), (args.conf, '--conf')):
            if _same_file(args.out, other):
                return _fail('--out is the same file as %s; it must be a new file' % flag)
        if os.path.lexists(args.out):
            return _fail('--out %s already exists; it must be a new file' % args.out)
    if args.json is not None:
        for other, flag in ((args.db, '--db'), (args.conf, '--conf'), (args.out, '--out')):
            if other is not None and _same_file(args.json, other):
                return _fail('--json is the same file as %s' % flag)
        if os.path.lexists(args.json):
            return _fail('--json %s already exists; it must be a new file' % args.json)

    try:
        db_bytes = _read(args.db)
        conf_text = _read(args.conf).decode('latin-1')
    except OSError as exc:
        return _fail(str(exc))
    db_text = db_bytes.decode('latin-1')
    try:
        db = parse(db_text)
    except ParseError as exc:
        return _fail('%s: %s' % (args.db, exc))
    try:
        conf = parse(conf_text)
    except ParseError as exc:
        return _fail('%s: %s' % (args.conf, exc))
    try:
        rule = read_name_rule(conf)
        section = nickserv_section(conf)
        _handles(db, section)
    except (NameRuleError, InputError) as exc:
        return _fail(str(exc))

    settings = keycloak_settings(conf)
    for key, value in (('url', args.keycloak_url), ('realm', args.realm), ('client_id', args.client_id)):
        if value:
            settings[key] = value
    if args.client_secret_file:
        try:
            settings['secret'] = _read(args.client_secret_file).decode('utf-8').rstrip('\r\n')
        except (OSError, UnicodeDecodeError) as exc:
            return _fail('--client-secret-file: %s' % exc)
    missing = [flag for key, flag in (('url', 'keycloak_url / --keycloak-url'), ('realm', 'keycloak_realm / --realm'),
                                      ('client_id', 'keycloak_client_id / --client-id'),
                                      ('secret', 'keycloak_client_secret / --client-secret-file'))
               if not settings[key]]
    if missing:
        return _fail('no Keycloak setting for: %s' % ', '.join(missing))

    try:
        keycloak = (connect or KeycloakClient)(settings)
        keycloak.check()
        rules = realm_username_rules(keycloak.profile)
    except (RequestRefused, KeycloakUnreachable, ValueError) as exc:
        return _fail('Keycloak: %s' % exc)
    if rules is None:
        rules = default_username_rules(args.name_min, args.name_max)

    report = bind(db, keycloak.lookup, rule, rules, section)
    print(_report_text(report, args.db, settings, section))

    if args.json is not None:
        try:
            with open(args.json, 'x', encoding='ascii') as f:
                json.dump(_report_json(report), f, indent=2)
                f.write('\n')
        except OSError as exc:
            return _fail('--json: %s' % exc)

    if args.out is not None:
        out_text = write_bound(db_text, db, report.bound, section)

        def check():
            verify_output(db, _read(args.out).decode('latin-1'), report.bound, section)
            if _read(args.db) != db_bytes:
                raise VerifyError('%s changed while this ran: is X3 still running? Stop it and work on a copy'
                                  % args.db)
        problem = _write_new_file(args.out, out_text.encode('latin-1'), check)
        if problem:
            return _fail(problem)
        print('\nwrote %s: %d kc_id entries added, verified' % (args.out, len(report.bound)))
        _keep_owner_and_mode(args.out, args.db)

    return 2 if report.needs_a_look() else 0


if __name__ == '__main__':
    sys.exit(main())
