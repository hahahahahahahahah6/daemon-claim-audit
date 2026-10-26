import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from daemon_claim_audit.audit import audit, families
from daemon_claim_audit.cli import main
from daemon_claim_audit.phrases import DAEMON, NODAEMON


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([str(self.root)] + list(args))
        return code, out.getvalue(), err.getvalue()

    def test_bad_exact(self):
        self.write('README.md', 'runs in the background')
        code, out, _ = self.cli()
        self.assertEqual((code, out), (2, 'FAIL\ndocumented-daemon-claim-false HIGH\n'))

    def test_negative_exact(self):
        self.write('README.md', 'does not run as a daemon')
        self.write('app.py', 'f(daemon=True)')
        self.assertEqual(audit(self.root)['findings'], [{'rule': 'documented-no-daemon-claim-false', 'severity': 'HIGH', 'path': 'README.md'}])

    def test_no_source(self):
        self.write('README.md', 'no daemon mode')
        self.assertEqual(audit(self.root)['status'], 'PASS')
        self.write('README.md', 'daemon mode')
        self.assertEqual(audit(self.root)['findings'][0]['severity'], 'HIGH')

    def test_fences_inline_wrapping(self):
        for text, expected in [('```text\ndaemon mode\n```', set()), ('~~~\ndaemon mode\n~~~', set()), ('`daemon mode`', {'DAEMON'}), ('runs in the\nbackground', {'DAEMON'}), ('runs in the\n\nbackground', set()), ('background-mode', {'DAEMON'}), ('the daemon handles requests; background jobs', set())]:
            with self.subTest(text=text):
                self.assertEqual(families(text), expected)

    def test_word_boundaries(self):
        for text in ('daemon model', 'daemon modes', 'background processes',
                     'a background processing job', 'daemonmodel'):
            with self.subTest(text=text):
                self.assertEqual(families(text), set())
        self.assertEqual(families('runs in the background.'), {'DAEMON'})

    def test_spans(self):
        for phrase in NODAEMON:
            self.assertEqual(families(phrase), {'NODAEMON'})
        self.assertEqual(families('no daemon mode; runs detached'), {'NODAEMON', 'DAEMON'})

    def test_medium_priority(self):
        self.write('tests/docs/a.md', 'daemon mode')
        self.assertEqual(self.cli()[0], 2)
        code, out, _ = self.cli('--fail-on', 'HIGH', '--json')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['findings'][0]['severity'], 'MEDIUM')
        self.write('docs/z.md', 'daemon mode')
        self.write('docs/y.md', 'daemon mode')
        result = audit(self.root)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['path'], 'docs/y.md')

    def test_ignore(self):
        self.write('README.md', 'daemon mode')
        self.write('app.py', 'f(daemon=True)')
        self.assertEqual(self.cli('--ignore', '*.py')[0], 2)
        self.assertEqual(self.cli('--ignore', 'README.md')[0], 0)

    def test_errors(self):
        self.write('app.py', 'def :')
        self.assertEqual(self.cli()[0], 1)
        self.assertEqual(main([str(self.root / 'missing')]), 1)
        self.assertEqual(self.cli('--invalid')[0], 1)
        self.assertEqual(self.cli('--fail-on', 'LOW')[0], 1)

    def test_unreadable(self):
        self.write('README.md', 'hello')
        with patch.object(Path, 'read_text', side_effect=PermissionError('unreadable')):
            self.assertEqual(self.cli()[0], 1)

    def test_env_never_opened(self):
        self.write('.env', 'daemon mode ENV_GUARD_MARKER')
        original = Path.read_text
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', guarded):
            code, out, err = self.cli('--json')
        self.assertEqual(code, 0)
        self.assertNotIn('ENV_GUARD_MARKER', out + err)

    def test_symlinks(self):
        outside = self.write('outside.txt', 'daemon mode')
        (self.root / 'README.md').symlink_to(outside)
        (self.root / 'docs').symlink_to(self.root, target_is_directory=True)
        self.assertEqual(audit(self.root)['claims'], [])

    def test_json_verbose_version_module(self):
        self.write('README.md', 'daemon mode')
        result = json.loads(self.cli('--json')[1])
        self.assertEqual(set(result), {'status', 'evidence', 'claims', 'findings'})
        self.assertIn('HIGH README.md', self.cli('--verbose')[1])
        self.assertEqual(self.cli('--fail-on', 'MEDIUM')[0], 2)
        run = subprocess.run([sys.executable, '-m', 'daemon_claim_audit', '--version'], capture_output=True, text=True)
        self.assertEqual((run.returncode, run.stdout.strip()), (0, '0.1.0'))

    def test_self_audit(self):
        result = audit(Path(__file__).resolve().parents[1])
        self.assertEqual((result['status'], result['claims']), ('PASS', []))


def evidence_test(source, expected, name='app.py'):
    def test(self):
        self.write('README.md', 'daemon mode')
        self.write(name, source)
        result = audit(self.root)
        self.assertEqual(bool(result['evidence']), expected)
        self.assertEqual(result['status'], 'PASS' if expected else 'FAIL')
    return test


GOOD = [
    'f(daemon=True)', 't.daemon = True', 't.daemon: bool = True',
    't.setDaemon(True)',
    'import subprocess as sp\nsp.Popen([], start_new_session=True)',
    'from subprocess import Popen as P\nP([], creationflags=DETACHED_PROCESS)',
    'import subprocess\nsubprocess.Popen([], creationflags=CREATE_NEW_PROCESS_GROUP | 1)',
    'import os as o\no.setsid()',
    'from os import fork, setsid\ndef f():\n fork()\n setsid()',
    'import daemon as d\nd.DaemonContext()',
    'from daemon import DaemonContext as D\nD()',
    'import daemonize as d\nd.daemonize()',
    'from daemonize import daemonize as d\nd()',
    'import daemon\ndaemon.daemonize()',
]
BAD = [
    'import daemon', 'import daemonize', 'f(daemon=False)', 't.daemon=False',
    't.setDaemon(False)', 'import subprocess\nsubprocess.Popen([], start_new_session=False)',
    'import subprocess\nsubprocess.Popen([])', 'import os\nos.fork()',
    'from threading import Thread\nThread()',
    'def daemonize():\n pass\ndaemonize()',
    '"os.setsid()"\n# f(daemon=True)',
    'import signal\nsignal.signal(2, lambda: None)',
    'while True:\n pass',
]
for index, source in enumerate(GOOD):
    setattr(AuditTests, 'test_evidence_%02d' % index, evidence_test(source, True))
for index, source in enumerate(BAD):
    setattr(AuditTests, 'test_not_evidence_%02d' % index, evidence_test(source, False))
for index, (name, text, expected) in enumerate([
    ('worker.service', '[Service]\nExecStart=/bin/true', True),
    ('worker.service', '[Service]', False),
    ('worker.service', 'ExecStart=/bin/true', False),
    ('tests/worker.service', '[Service]\nExecStart=/bin/true', False),
    ('tests/app.py', 'f(daemon=True)', False),
    ('test_app.py', 'f(daemon=True)', False),
]):
    setattr(AuditTests, 'test_file_evidence_%02d' % index, evidence_test(text, expected, name))
for index, phrase in enumerate(DAEMON):
    def test(self, phrase=phrase):
        self.assertEqual(families(phrase.upper()), {'DAEMON'})
    setattr(AuditTests, 'test_phrase_%02d' % index, test)
