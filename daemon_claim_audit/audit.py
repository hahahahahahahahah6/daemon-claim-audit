"""Static documentation and source inspection; inspected code is never executed."""
import ast
import fnmatch
import os
from pathlib import Path
import re

from .phrases import DAEMON, NODAEMON


def normalize(text):
    return ' '.join(text.lower().replace('-', ' ').split())


def _pattern(phrases):
    return re.compile(r'(?<!\w)(?:' + '|'.join(re.escape(p) for p in
                      sorted(phrases, key=len, reverse=True)) + r')(?!\w)')


NEG_RE = _pattern(NODAEMON)
POS_RE = _pattern(DAEMON)


def families(text):
    paragraphs = []
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if fence:
            if re.match(r'^\s{0,3}' + re.escape(fence[0]) + '{' + str(len(fence)) + r',}\s*$', line):
                fence = None
            continue
        if match:
            fence = match.group(1)
            paragraphs.append(normalize(' '.join(lines)))
            lines = []
        elif not line.strip():
            paragraphs.append(normalize(' '.join(lines)))
            lines = []
        else:
            lines.append(line)
    paragraphs.append(normalize(' '.join(lines)))
    found = set()
    for paragraph in paragraphs:
        spans = [(m.start(), m.end()) for m in NEG_RE.finditer(paragraph)]
        if spans:
            found.add('NODAEMON')
        remaining = list(paragraph)
        for start, end in spans:
            remaining[start:end] = ' ' * (end - start)
        if POS_RE.search(''.join(remaining)):
            found.add('DAEMON')
    return found


def python_evidence(text, filename):
    tree = ast.parse(text, filename=filename)
    aliases = {}
    library = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
                library |= item.name in ('daemon', 'daemonize')
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases[item.asname or item.name] = (node.module or '') + '.' + item.name
            library |= node.module in ('daemon', 'daemonize')

    def dotted(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return dotted(node.value) + '.' + node.attr
        return ''

    def true(node):
        return isinstance(node, ast.Constant) and node.value is True

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and true(node.value):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Attribute) and t.attr == 'daemon' for t in targets):
                return True
        if not isinstance(node, ast.Call):
            continue
        name = dotted(node.func)
        if any(k.arg == 'daemon' and true(k.value) for k in node.keywords):
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'setDaemon' and node.args and true(node.args[0]):
            return True
        if name == 'os.setsid':
            return True
        if library and name in ('daemon.DaemonContext', 'daemonize.daemonize', 'daemon.daemonize'):
            return True
        if name == 'subprocess.Popen':
            for kw in node.keywords:
                if kw.arg == 'start_new_session' and true(kw.value):
                    return True
                if kw.arg == 'creationflags' and any(isinstance(n, ast.Name) and n.id in ('DETACHED_PROCESS', 'CREATE_NEW_PROCESS_GROUP') for n in ast.walk(kw.value)):
                    return True
    return False


def audit(root, ignore=(), fail_on='MEDIUM'):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('ROOT must be a directory')
    claims = []
    evidence = []
    paths = []
    def walk_error(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink() and not any(fnmatch.fnmatchcase((Path(directory) / d).relative_to(root).as_posix(), g) for g in ignore))
        for name in sorted(files):
            path = Path(directory) / name
            rel = path.relative_to(root)
            if path.is_symlink() or name == '.env' or name.startswith('.env.'):
                continue
            if any(fnmatch.fnmatchcase(rel.as_posix(), g) for g in ignore):
                continue
            paths.append((rel, path))
    for rel, path in sorted(paths):
        doc = rel.as_posix() == 'README.md' or (rel.suffix == '.md' and 'docs' in rel.parts[:-1])
        source = rel.suffix == '.py' and 'tests' not in rel.parts and not rel.name.startswith('test_')
        service = rel.suffix == '.service' and 'tests' not in rel.parts
        if not (doc or source or service):
            continue
        text = path.read_text(encoding='utf-8')
        if doc:
            for family in sorted(families(text)):
                claims.append({'family': family, 'path': rel.as_posix(), 'severity': 'MEDIUM' if 'tests' in rel.parts else 'HIGH'})
        if (source and python_evidence(text, str(path))) or (service and '[Service]' in text and 'ExecStart' in text):
            evidence.append(rel.as_posix())
    findings = []
    for family, false in [('DAEMON', not evidence), ('NODAEMON', bool(evidence))]:
        candidates = [c for c in claims if c['family'] == family]
        if false and candidates:
            claim = sorted(candidates, key=lambda c: (c['severity'] != 'HIGH', c['path']))[0]
            findings.append({'rule': 'documented-' + ('daemon' if family == 'DAEMON' else 'no-daemon') + '-claim-false', 'severity': claim['severity'], 'path': claim['path']})
    failed = any(f['severity'] == 'HIGH' or fail_on == 'MEDIUM' for f in findings)
    return {'status': 'FAIL' if failed else 'PASS', 'evidence': evidence, 'claims': claims, 'findings': findings}
