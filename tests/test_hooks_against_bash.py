"""The guard against a real shell.

Generated commands run in bash and in zsh (the shell of a mac) with stub programs that only log their arguments. Whatever the shell
really runs as `python -m boxed` must be blocked by the guard, unless the guard without its git and pytest exemptions lets it through
too and so did the guard it replaced (holes that were there before, like a module name built at run time).

The second part does the same for the allowances of the path guard: whatever the old guard blocked and the guard passes now
must be an intended allowance, and what the shell really does with it must be harmless. Then come the wildcards (the matcher against
both shells, whole commands with patterns in a world whose links lead out of the mirror) and the text written into files.
"""

import itertools
import os
import random
import re
import shlex
import subprocess
import sys
from collections import Counter, namedtuple
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import pytest
from hypothesis import HealthCheck, assume, example, given, settings
from hypothesis import strategies as st

import boxed.hooks as hooks
from boxed.config import ProjectConfig
from boxed.hooks import _runs_boxed, _shell_words, boxed_reveal, hook_pre_tool_use
from boxed.journal import Journal
from boxed.keys import default_keystore
from boxed.vault import Vault
from boxed.workspace import create_workspace

pytestmark = pytest.mark.skipif(not os.path.exists("/bin/bash"), reason="needs bash")
# The Bash tool runs the user's shell, which is zsh on a mac and bash elsewhere: the guard has to hold against both. zsh runs without its
# startup files (-f), bash without rc and profile.
SHELLS = {"bash": ["/bin/bash", "--norc", "--noprofile", "-c"], "zsh": ["/bin/zsh", "-f", "-c"]}
SHELL_PARAMS = [pytest.param(name, marks=pytest.mark.skipif(not os.path.exists(argv[0]), reason=f"needs {name}")) for name, argv in SHELLS.items()]

OLD_MODULE = re.compile(r"-m\s*boxed\b|boxed-native-host\b|boxed\.native_host\b|\bimport\s+boxed\b|\bfrom\s+boxed[\w.]*\s+import\b")
REVEALING = ("restore", "mask", "workspace", "journal", "restore-file", "mask-file")  # boxed commands that show or touch originals
STUB = "#!/bin/bash\n{ printf '%s\\x1f' \"$(basename \"$0\")\" \"$@\"; printf '\\x1e'; } >> \"$LOG\"\n"
WRAPPER = '#!/bin/bash\nexec "$@"\n'


def old_guard(command):
    """boxed.hooks._runs_boxed before the exemptions (9f6cd1f)."""
    spelled, words = _shell_words(command)
    return any("boxed" in text and (boxed_reveal().search(text) or OLD_MODULE.search(text)) for text in (spelled, " ".join(words)))


def new_guard(command):
    """The module check of hook_pre_tool_use, with a cd taken to stay inside the mirror (the hook looks at where it goes)."""
    moved = hooks._after_cd(command)
    return _runs_boxed(*_shell_words(moved[1] if moved and hooks._cd_is_exact(moved[0]) else command))


def python_module(args):
    """The module `python args` runs, by Python's option rules: a cluster ending in m takes the next word."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-" or not arg.startswith("-"):
            return None
        if arg.startswith("--"):
            i += 2 if arg == "--check-hash-based-pycs" else 1
            continue
        for j, letter in enumerate(arg[1:], 1):
            if letter == "m":
                return arg[j + 1 :] or (args[i + 1] if i + 1 < len(args) else "")
            if letter == "c":
                return None
            if letter in "WX":  # takes the rest of the word, or the next word
                if j == len(arg) - 1:
                    i += 1
                break
        i += 1
    return None


def uv_module(args):
    if "run" not in args:
        return None
    flagged = False
    for arg in args[args.index("run") + 1 :]:
        if arg == "--module" or re.fullmatch(r"-[A-Za-z]*m", arg):
            flagged = True
        elif arg == "-" or not arg.startswith("-"):
            return arg if flagged else None
    return None


def boxed_module_runs(log):
    runs = []
    for record in (log.read_bytes().decode() if log.exists() else "").split("\x1e"):
        name, *args = record.split("\x1f")[:-1] or [""]
        module = python_module(args) if name in ("python3", "python", "p") else uv_module(args) if name == "uv" else None
        if module and (module == "boxed" or module.startswith("boxed.")):
            runs.append((name, args))
        elif name == "boxed" and args[:1] and args[0] in REVEALING:  # the command itself, as a stub
            runs.append((name, args))
    return runs


@pytest.fixture(scope="module", params=SHELL_PARAMS)
def shell(request, tmp_path_factory):
    root = tmp_path_factory.mktemp("shell")
    (root / "bin").mkdir()
    for script, names in ((STUB, ("python3", "python", "pytest", "uv", "boxed")), (WRAPPER, ("env", "sudo", "nohup", "xargs"))):
        for name in names:
            (root / "bin" / name).write_text(script)
            (root / "bin" / name).chmod(0o755)
    (root / "work" / "src").mkdir(parents=True)
    (root / "work" / "p").symlink_to(root / "bin" / "python3")
    count = itertools.count()

    def run(command):
        log = root / f"log{next(count)}"  # a command may leave a background job that logs late: one log file for each
        env = {"PATH": f"{root / 'bin'}:/usr/bin:/bin", "LOG": str(log), "PY": "python3", "HOME": str(root), "LC_ALL": "C",
               "GIT_CEILING_DIRECTORIES": str(root), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}  # git itself is real
        subprocess.run([*SHELLS[request.param], command], cwd=root / "work", env=env, timeout=10, stdin=subprocess.DEVNULL, capture_output=True)
        runs = boxed_module_runs(log)
        log.unlink(missing_ok=True)
        return runs

    run.root = root
    return run


def test_the_shell_helper_leaves_no_log_files(shell):
    assert shell("python3 -m boxed.cli x")
    assert not list(shell.root.glob("log*"))


def test_the_shell_model_sees_real_module_runs(shell):
    for command in ("python3 -m boxed.cli x", "> git python3 -Imboxed", "git commit -m boxed; python3 -m $(echo boxed)",
                    "git commit -m boxed; python3 -m >/dev/null boxed.cli", "uv run --module boxed", "$PY -m boxed",
                    'git() { python3 "$@"; }; git -m boxed', "git -c alias.x='!python3' x -m boxed", 'python3 "$(echo -m)" boxed',
                    "git commit # -m '\npython3 -m boxed.cli --help\n# '",  # a comment: bash never sees the quote
                    "git commit <<'EOF' # -m '\nbody\nEOF\npython3 -m boxed.cli --help\n# '"):
        assert shell(command), command
    for command in ("git commit -m boxed", "pytest -m boxed", "python3 -m pytest -m boxed", "python3 -c 'import os' -m boxed",
                    "git -c alias.commit='!python3' commit -m boxed"):  # git ignores an alias that hides one of its commands
        assert not shell(command), command


PROGRAMS = ("git", "git", "pytest", "pytest", "python3", "python", "uv run", "env python3", "sudo python3", "./p", "$PY", "echo", "true",
            "git -C src", "FOO=1 git", "FOO=1 python3", "time", "!", "git -c alias.x='!python3' x", "git -c alias.ci=!python3 ci",
            "git -c alias.commit=x commit")
ARGS = ("-m", "-m", "-am", "-Im", "-qm", "-I", "-W ignore", "-c x", "boxed", "boxed", "boxed.cli", "boxed:", "-mboxed", "-Imboxed.cli", "msg",
        "commit", "--module", "'boxed'", '"-m"', "-m\\ boxed", "$(echo boxed)", "{-m,boxed}", "$'\\x2dm'", '"$(echo -m)"', "2>&1",
        ">/dev/null", "> out", "< in", "&>out", ">>out", "--", "#", "'", '"', "<<'EOF'")
LEADS = ("", "", "", "> git ", ">git ", ">& git ", "< pytest ", ">>out ", "2>f ")
WRAPS = ("{}", "{}", "({})", "echo $({})", "echo `{}`", "{{ {}; }}", "bash -c '{}'")
DEFINITIONS = ('git() { python3 "$@"; }', 'git ( ) { python3 "$@"; }', 'function pytest { python3 "$@"; }', "pytest(){ python3 \"$@\";}",
               "eval 'git() { python3 \"$@\"; }'")  # git or pytest becomes Python
SEPARATORS = (" ; ", " && ", " || ", " | ", "\n", " & ", ";", "&&")
# the lines the git and pytest exemption is meant for: a random program with random arguments seldom builds one
MESSAGE_LINES = ("git commit -m boxed", "git commit -am boxed", "git tag -m boxed v1", 'git commit -m "boxed: fix"', "pytest -m boxed", "pytest -mboxed -q",
                 "git -C src commit -m boxed", "git commit -m boxed > out.txt", "git commit -m boxed 2>/dev/null", "pytest -m 'boxed and not slow'")
segments = st.one_of(
    st.builds(lambda wrap, lead, program, args: wrap.format(f"{lead}{program} {' '.join(args)}"), st.sampled_from(WRAPS),
              st.sampled_from(LEADS), st.sampled_from(PROGRAMS), st.lists(st.sampled_from(ARGS), max_size=5)),
    st.sampled_from(DEFINITIONS),
    st.sampled_from(MESSAGE_LINES),
)
chains = st.builds(lambda first, rest: first + "".join(sep + segment for sep, segment in rest), segments,
                   st.lists(st.tuples(st.sampled_from(SEPARATORS), segments), max_size=2))
RUNS = ("python3 -m boxed.cli --help", "python -Im boxed", "./p -m boxed", "uv run -m boxed", "env python3 -m boxed.cli", "$PY -m boxed")
# a comment that opens a quote another comment closes: bash skips both, a shlex parse reads what lies between as one word
traps = st.builds("{} # -m {}\n{}\n# {}{}".format, st.sampled_from(("git commit", "pytest", "git -C src tag", "git commit -m boxed")),
                  st.sampled_from(("'", '"')), st.sampled_from(RUNS) | segments, st.sampled_from(("", "y ")), st.sampled_from(("'", '"')))
CD_PREFIXES = ("", "", "", "cd ./src && ", "cd ./src&&", "cd . && ", "cd ./src && ", "cd src && ", "cd ./src ; ", "cd ./src\n", "cd ./src && cd .. && ",
               "cd .. && ", "cd ./src || ", "cd ./src & ", "cd ./src | ", "cd ./src && (", "cd ./src && { ", "cd ./src && ! ", "cd ./src && time ",
               "cd ./src && FOO=1 ", "cd rel5/.. && ", "cd src/.. && ")
commands = st.builds("{}{}".format, st.sampled_from(CD_PREFIXES), chains | traps)


@settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(commands)
@example("cd ./src && git commit -m boxed; python3 -m boxed.cli")
@example("cd ./src && git commit -m boxed && python3 -m boxed.cli")
@example("cd ./src && git commit # -m '\npython3 -m boxed.cli --help\n# '")
@example("cd ./src && git commit -m boxed\npython3 -m boxed.cli --help")
@example("cd ./src && git commit -m boxed | python3 -m boxed.cli")
@example("cd ./src && > git python3 -m boxed")
@example("cd ./src && git commit -m boxed & python3 -m boxed.cli")
@example('cd ./src && git() { python3 "$@"; } && git -m boxed')
@example("cd ./src && git -c alias.x='!python3' x -m boxed.cli re{store,}")
@example("cd ./src && git commit -m boxed; python3 -m $(echo boxed)")
@example("cd ./src && git commit -m boxed; python3 {-m,boxed}")
@example("> git python3 -m boxed")
@example(">& git python3 -mboxed")
@example("true &&>git python3 -m boxed")
@example("git commit -m boxed; python3 -m >/dev/null boxed.cli")
@example("git commit -m boxed; python3 -m $(echo boxed)")
@example("pytest -m boxed; uv run --module >/dev/null boxed")
@example("git commit -m boxed & ./p -Im boxed")
@example("git commit # -m '\npython3 -m boxed.cli --help\n# '")
@example('pytest # -m "\n./p -m boxed\n# "')
@example("git commit -m boxed # -m '\npython3 -m boxed.cli --help\n# '")
@example("git commit <<'EOF' # -m '\nbody\nEOF\npython3 -m boxed.cli --help\n# '")
@example("git -c alias.x='!python3' x -m boxed.cli re{store,}")
@example("git -c alias.ci=!python3 ci -m boxed")
@example('python3 "$(echo -m)" boxed.cli')
@example("git commit -m boxed; python3 {-m,boxed}")
@example('git commit -m boxed && echo "$(python3 {-m,boxed})"')
@example("pytest -m boxed; ./p $'\\x2dm' boxed")
@example('git() { python3 "$@"; }; git -m boxed')
@example('git ( ) { python3 "$@"; } && git -m boxed')
@example("eval 'pytest() { python3 \"$@\"; }'; pytest -m boxed.cli")
def test_no_exemption_hides_a_module_run_that_bash_makes(shell, command):
    if not shell(command) or new_guard(command):
        return
    with mock.patch.object(hooks, "_only_messages", lambda command: False), mock.patch.object(hooks, "_after_cd", lambda command: None):
        assert not new_guard(command) and not old_guard(command), command


# A string that a second shell reads later hides the name with inner quotes or backslashes. In '...' they reach that shell as
# they are (bo""xed, bo\xed); in "..." the same with single quotes (bo''xed).
INNER = "{name} {sub} x", "python3 -m {name}.cli {sub} x"
IN_SINGLE = (("bo\"\"xed", "bo\\xed", "b\"o\"xed"), ("restore", "re\"\"store", "mask"),
             ("sh -c '{}'", "bash -c '{}'", "env sh -c '{}'", "echo x | xargs sh -c '{}'", "find . -maxdepth 0 -exec sh -c '{}' \\;"))
IN_DOUBLE = (("bo''xed", "b'o'xed"), ("restore", "re''store", "mask"), ('sh -c "{}"', 'bash -c "{}"', 'echo x | xargs sh -c "{}"'))


def nested(group):
    names, subs, shells = group
    return st.builds(lambda shell, form, name, sub: shell.format(form.format(name=name, sub=sub)), st.sampled_from(shells),
                     st.sampled_from(INNER), st.sampled_from(names), st.sampled_from(subs))


nested_shells = nested(IN_SINGLE) | nested(IN_DOUBLE)


@settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(nested_shells)
@example("sh -c 'python3 -m bo\"\"xed.cli re\"\"store x'")
@example('bash -c "bo\'\'xed re\'\'store x"')
@example("sh -c 'bo\\xed restore x'")
def test_a_nested_shell_cannot_hide_the_name_from_the_guard(shell, command):
    if shell(command):
        assert new_guard(command), command


# ---- the allowances of the path guard -----------------------------------------------------------------------------------------
#
# Each allowance passes commands the guard used to block. The old guard is the new one with every allowance switched off where it
# is decided (old_rules). A command the old guard blocked and the guard passes now must be an intended allowance (a second opinion
# on its shape, written here) and what bash really does with it must be harmless: no program but the intended ones runs, no argument
# of a program reaches protected data from the folder it really ran in, no protected file changes and boxed is not run.

TRACE = "\x1f\x1e@ "  # PS4: bash 3.2, the only bash on a mac, cannot send the trace to another descriptor; a marker tells it from stderr
LOGGING_STUB = (
    "#!/bin/bash\n"
    "{ printf '%s\\x1f' \"${0##*/}\" \"$@\"; printf '\\x1e'; } >> \"$LOG\"\n"  # as STUB, for boxed_module_runs
    "{ printf '%s\\x1f%s\\x1f' \"${0##*/}\" \"$PWD\"; for a in \"$@\"; do printf '%s\\x1f' \"$a\"; done; printf '\\x1e'; } >> \"$LOGC\"\n"
)  # name, folder, arguments
STUBBED = ("cat ls head tail grep rg find sed awk sleep python3 python uv boxed git pytest expr sh tee cp mv rm touch ln mkdir curl wc "
           "sort tr stat file du tree bc ssh open node").split()
BUILTINS = {"cd", "echo", "printf", "pwd", "eval", "exec", "command", "builtin", "source", ".", "exit", "kill", "read", "set", "unset", "export", "trap",
            "wait", "test", "[", "true", "false", ":", "time", "pushd", "popd", "alias", "hash", "type", "ulimit", "umask"}
EXISTING = {*STUBBED, "env", "sudo", "nohup", "xargs", *BUILTINS}  # what bash can really run in the world: a name outside it is "not found"
Run = namedtuple("Run", "trace externals modules changed")


@contextmanager
def old_rules():
    """The guard as it was before the path allowances (and before it read a path with a .. in it the way a cd folds it, the names a
    wildcard stands for, and a word as written as well as up to its first wildcard character: PATH_LIMIT 0 switches that last one off)."""
    with mock.patch.object(hooks, "_expr_line", lambda command: False), \
         mock.patch.object(hooks, "_arithmetic_words", lambda command: command), \
         mock.patch.object(hooks, "_prints_only", lambda command: False), \
         mock.patch.object(hooks, "_after_cd", lambda command: None), \
         mock.patch.object(hooks._Guard, "glob_blocked", lambda self, pattern, cwd, holders, scan: False), \
         mock.patch.object(hooks, "PATH_LIMIT", 0), \
         mock.patch.object(hooks._Guard, "ways", staticmethod(lambda value, cwd: [hooks._resolve(value, cwd)])):
        yield


class World:
    """A project, a boxed home with its mirror and a second mirror, and a bash that logs what it really runs in the mirror."""

    def __init__(self, root, shell="bash"):
        self.root, self.home = root, root / "home"  # $HOME is above the project and above the boxed home, as on a real machine
        self.shell = SHELLS[shell]
        self.boxed_home = self.home / ".boxed"
        self.counter = itertools.count()
        for name in ("bin", "logs"):
            (root / name).mkdir()
        for script, names in ((LOGGING_STUB, STUBBED), (WRAPPER, ("env", "sudo", "nohup", "xargs"))):
            for name in names:
                (root / "bin" / name).write_text(script)
                (root / "bin" / name).chmod(0o755)
        made = []
        with pytest.MonkeyPatch.context() as env:
            env.setenv("BOXED_HOME", str(self.boxed_home))
            env.setenv("BOXED_KEYSTORE", "insecure-file")
            env.setenv("GIT_CONFIG_GLOBAL", os.devnull)  # git reads neither the user's nor the system's configuration here
            env.setenv("GIT_CONFIG_NOSYSTEM", "1")
            self.boxed_home.mkdir(parents=True)
            keys = default_keystore()
            for name in ("proj2", "other"):
                repo = self.home / name
                (repo / "src").mkdir(parents=True)
                (repo / ".env").write_text("DB_PASSWORD=hunter22\n")
                (repo / "src" / "app.py").write_text("print('ivan.petrov@acme.com')\n")
                subprocess.run(["git", "init", "-q", str(repo)], check=True)
                made.append(create_workspace(repo, level=2, config=ProjectConfig(), vault=Vault(self.boxed_home / "vault.db", keys),
                                             journal=Journal(self.boxed_home / "journal.jsonl", keys), home=self.boxed_home).workspace)
        self.original, self.ws = (self.home / "proj2").resolve(), made[0]
        self.mirror = self.ws.mirror
        (self.mirror / "link").symlink_to(self.original)  # a way out of the mirror, as an agent can make one
        (self.mirror / "src" / "link2").symlink_to(self.original)  # and one in a folder, which a cd makes the start of the paths
        (self.mirror / "src" / "a" / "b" / "c" / "d").mkdir(parents=True)
        (self.mirror / "rel5").symlink_to("src/a/b/c/d")  # a link that stays in the mirror, five folders down: rel5/.. is not src/a/b/c
        (self.mirror / "a{").mkdir()  # a folder whose name holds a brace that closes nothing: a{/../../vault.db goes through it
        (self.mirror / "secret").symlink_to(self.original / ".env")  # a link to a file, which a pattern can stand for as well
        (self.mirror / ".hid").symlink_to(self.original)  # and one a hidden name hides from * in bash, but not in a zsh with globdots
        (self.mirror / "7").symlink_to(self.original)  # a name that is the value of arithmetic: $(( 14 / 2 )) is 7 (no seed has that value)
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            self.guard = hooks._Guard(self.ws, self.boxed_home)

    def fill(self, text):
        """§H is the home of the world and §M its mirror."""
        return text.replace("§H", str(self.home)).replace("§M", str(self.mirror))

    def blocks(self, command):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(self.mirror)}
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            try:
                return hook_pre_tool_use(payload, self.boxed_home).exit_code == 2
            except ValueError:  # a NUL in a path: the hook command turns any error inside a mirror into a block, and bash takes no NUL either
                return True

    def old_blocks(self, command):
        with old_rules():
            return self.blocks(command)

    def file_call(self, tool_name, **fields):
        """What the hook says (0 or 2) to a call of a tool that writes a file, from the mirror."""
        payload = {"tool_name": tool_name, "tool_input": fields, "cwd": str(self.mirror)}
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            return hook_pre_tool_use(payload, self.boxed_home).exit_code

    def snapshot(self):
        """The protected data on disk, as the guard defines it: the project, the parts of the boxed home it lists and the other mirrors.
        What a command writes in the mirror, or in a place the guard does not protect, is its own business."""
        found = {}
        for top in [*self.guard.roots, *(p for p in self.guard.workspaces.iterdir() if p != self.mirror)]:
            if top.exists():
                for path in [top, *top.rglob("*")]:
                    stat = path.lstat()
                    found[str(path)] = (stat.st_mode, stat.st_size, stat.st_mtime_ns)
        return found

    @staticmethod
    def reach(path):
        """Where a program that opens this path ends up, or None: a missing folder on the way ends the lookup (ENOENT) where a lexical
        collapse of .. would go on; a missing last name may still be created."""
        try:
            return (path.parent.resolve(strict=True) / path.name).resolve()
        except OSError:
            return None

    def run(self, command):
        n = next(self.counter)
        log, logc = self.root / "logs" / f"l{n}", self.root / "logs" / f"c{n}"
        before = self.snapshot()
        # CDPATH is the user's: `cd proj2` goes to $HOME/proj2 whatever the mirror holds
        env = {"PATH": str(self.root / "bin"), "LOG": str(log), "LOGC": str(logc), "HOME": str(self.home), "LC_ALL": "C", "PS4": TRACE,
               "CDPATH": str(self.home)}
        done = subprocess.run([*self.shell, "set -x\n" + command], cwd=self.mirror, env=env, timeout=10, stdin=subprocess.DEVNULL,
                              capture_output=True)
        # bash repeats the first character of PS4 once for each level of $( ), a subshell or a function
        marked = (re.fullmatch(r"\x1f+\x1e@ (.*)", line, re.DOTALL) for line in done.stderr.decode(errors="replace").split("\n"))
        trace = [found[1] for found in marked if found]
        records = (logc.read_bytes().decode() if logc.exists() else "").split("\x1e")
        fields = [record.split("\x1f")[:-1] for record in records if record]
        externals = [(f[0], f[1], f[2:]) for f in fields if len(f) >= 2]  # a job cut off by the end of the run may leave half a record
        modules = boxed_module_runs(log)
        for path in (log, logc):
            path.unlink(missing_ok=True)
        return Run(trace, externals, modules, self.snapshot() != before)

    def run_script(self, text):
        """What bash does when a file holding this text is run in the mirror."""
        path = self.root / "logs" / f"script{next(self.counter)}"
        path.write_text(text)
        try:
            return self.run(f". {path}")
        finally:
            path.unlink(missing_ok=True)

    def harm(self, run, family):
        """Why a real run was not harmless, or None."""
        if run.modules:
            return "ran boxed"
        if run.changed:
            return "changed protected data"
        for line in run.trace:
            try:
                words = shlex.split(line)
            except ValueError:
                words = line.split()
            if family in FAMILY_PROGRAMS and words and words[0] not in FAMILY_PROGRAMS[family] and words[0] in EXISTING:  # not found is not run
                return f"ran {words[0]}"
            if family == "print":  # what is printed need not be read, but a path it prints may not lie inside protected data
                for arg in (piece for word in words[1:] for piece in re.split(r"[=:]", word)):  # a = or : separates paths, as in PATH=a:b
                    if "$" in arg:  # a '$HOME' in quotes stays text, which the guard reads as the home folder: nothing to open either way
                        continue
                    if ("/" in arg or arg.startswith(("~", ".."))) and self.guard.blocked((self.mirror / arg).resolve(), holders=False):
                        return f"printed {arg!r}, which lies inside protected data"
        for name, cwd, args in run.externals:
            if family == "cd" and Path(cwd).resolve() != self.guard.mirror and self.guard.mirror not in Path(cwd).resolve().parents:
                return f"{name} ran in {cwd}, outside the mirror"
            for arg in () if name in READS_NO_FILES else args:
                reached = self.reach(Path(cwd) / arg)
                if reached is not None and self.guard.blocked(reached):
                    return f"{name} reached protected data with {arg!r} from {cwd}"
        return None


@pytest.fixture(scope="module", params=SHELL_PARAMS)
def world(request, tmp_path_factory):
    return World(tmp_path_factory.mktemp("world").resolve(), request.param)


FAMILY_PROGRAMS = {"expr": {"expr"}, "print": {"echo", "printf", "pwd"}, "cd": {"cd", "git", "pytest"}}  # arithmetic words may sit in any command
READS_NO_FILES = {"expr"}  # its arguments are numbers and signs, never paths: a "/" is a division
ARITHMETIC = ("expr 6 / 3", "expr 12 / 4 / 3", "expr 6 / 3 + 1", "expr 6 \\* 3 / 2", "echo $(( 6 / 3 ))", "ls $(( 6 / 3 ))",
              "ls -la $(( 6 / 3 )) src", "sleep $(( 6 / 3 ))", "git log -n $(( 12 / 4 ))", "echo $(( 6 / 3 )) $(( 8 / 2 ))")
# lines an allowance must keep blocked; §H is the home of the world, whose project is proj2: the value of the arithmetic finishes its name
ATTACKS = ('ls "§H/proj"$(( 6 / 3 ))', "ls §H/proj$(( 6 / 3 ))", "ls '§H/proj'$(( 6 / 3 ))", "ls ~/proj$(( 6 / 3 ))",
           'ls ~/"proj"$(( 6 / 3 ))', "cat §H/proj2/.env $(( 6 / 3 ))", "ls $(( 6 / 3 )) ~/..", "ls . $(( 6 / 3 )) ..", "ls $(( 6 / 3 )) §H",
           "expr 6 / 3 §H", "ls $(( 6 / 3 )) §H/.boxed", "ls $(( 6 / 3 )) ~/.boxed/workspaces/..",
           # a = or : inside a brace or a bracket is no cut between paths
           "head -n1 {{link,[x=x]},x}", "ls {link,[x=x]}", "ls {a=b,link}", "ls {x:y,link}",
           # the value of the word names a link out of the mirror
           "ls $(( 14 / 2 ))", "ls $(( 21 / 3 ))", "ls $(( 1 + 12 / 2 ))", "git -C $(( 49 / 7 )) log", "echo $(( 14 / 2 ))", "cat $(( 35 / 5 )) $(( 6 / 3 ))",
           # a brace that closes nothing is a name, quoted or not: the word is read as written, not only up to the brace
           "echo 'home:' \"../.{ME/.,.\"", "echo '../ws-x{'", "echo \"../ws-x{\"", "printf '%s' \"../{ws\"")
# the same through a folder called a{ (the world has one): up to the brace the word was inside the mirror, and the vault is not
BRACE_HOLES = ("cat ./a{/../../../vault.db", "cat 'a{/../../../vault.db'", "cat a{/../../../vault.db", "head -n1 ./a{/../../../vault.db")
# the same without a division sign, which the guard never looked at: the old guard passed them
ARITH_HOLES = ("ls $(( 4 + 3 ))", "ls $(( 10 - 3 ))", "ls $(( 50 % 43 ))", "ls $(( 2 * 3 + 1 ))", "cat $(( 3 + 4 )) src", "echo $(( 2 + 5 ))",
               "head -n1 $(( 12 - 5 ))", "ls $(( 4 + 3 )) ; true", "ls $(( 4 + 3 )) > out", "eval ls $(( 10 - 3 ))\n &",
               "ls $(( 4 + 3 )) # x", "cat $(( 3 + 4 )) | cat")
# echo, printf and pwd print words and read nothing; §P is a word that names a folder (see ANCESTORS, INSIDE and ODD below)
PRINTING = ("echo §P", "echo §P §P", "printf '%s\\n' §P", 'printf "%s\\n" §P', "echo -n §P", "echo 'home:' §P")
ANCESTORS = ("$HOME", '"$HOME"', "${HOME}", "~", "~/", "/", "..", "../..", "../../..", "$HOME/..", '"$HOME/.."', "~/.boxed", "§H/.boxed", "§H/.boxed/workspaces",
             "§H", "./..", "/..", "//")
INSIDE = ("§H/proj2", "§H/proj2/.env", "§H/.boxed/vault.db", "§H/.boxed/state", "§H/.boxed/workspaces/ws-x", "~/proj2", "$HOME/proj2",
          '"$HOME/proj2"', "~/.boxed/vault.db", "../ws-x", "../../vault.db", "../../state/x", "${HOME}/proj2/src", "$HOME/.boxed/journal.jsonl",
          "~/.boxed/journal.jsonl", "§H/proj2/", "§H//proj2", "~/./proj2", "$HOME/./proj2", "~/.boxed/bin", "~/.boxed/reports", "link/.env",
          "§H/PROJ2", "§H/Proj2/.env", "§H/.BOXED/vault.db", "~/.Boxed/state", "$HOME/PROJ2", "§H/.boxed/WORKSPACES/ws-x",
          "~/.boxed/workspaces/ws-x/y")
ODD = ("~/*", "$HOME/*", "~/{proj2,x}", "'~'", "~root", "~+", "~-", "$PWD", "$OLDPWD", "$HOME$HOME", "$HOMEX", "$HOME/", "$(ls /)", '"$(ls /)"',
       "$'~'", "\\~", "~\\\n", "$HOME\\\n/proj2", "/*", "/.*", "?", "[~]", "=ls", "a=~", "~/proj2/*", "~/.boxed/work*", "${HOME:-/}",
       "${HOME}x", "\"$HOME\"/proj2", "$HOME\"/proj2\"", "'$HOME'")
# cd <plain path> && <plain git or pytest line>; §M is the mirror. The path is . or starts with ./ or /, and has no ..: the shell does not search
# CDPATH for it and has no .. to fold before it follows a link. From src the project is one folder further up than from the mirror.
CD = ("cd ./src && git commit -m boxed", "cd ./src && pytest -m boxed", "cd . && git commit -am boxed", 'cd ./src && git commit -m "boxed: fix"',
      "cd §M && git tag -m boxed v1", "cd §M/src && pytest -m 'boxed and not slow'", "cd ./src/ && git commit -mboxed", "cd ./src&&git commit -m boxed",
      "cd ./src && git -C . commit -m boxed", "cd ./missing && git commit -m boxed", "cd ./src && git commit -m boxed -- app.py",
      "cd ./ && git commit -m boxed", "cd ./rel5 && git commit -m boxed", "cd ./src && git log -m boxed",
      "cd ./src && pytest -mboxed -q tests/test_a.py::test_b")
CD_ATTACKS = ("cd .. && git commit -m boxed", "cd ../.. && pytest -m boxed", "cd / && git commit -m boxed", "cd link && git commit -m boxed",
              "cd . && pytest -m boxed li*", "cd . && git commit -m boxed l?nk", "cd §H/PROJ2 && git commit -m boxed", "cd ./src && pytest -m boxed ~-/..",
              "cd link/src && pytest -m boxed", "cd §H/proj2 && git commit -m boxed", "cd ./src && git commit -m boxed ../../../../proj2/.env",
              "cd ./src && git diff -m boxed ../../../../proj2/.env", "cd ./src && git commit -m boxed && python3 -m boxed", "cd ./src && python3 -m boxed",
              "cd §M/.. && git commit -m boxed", "cd ./src && git commit -m boxed §H/proj2/.env", "cd ./src && git commit -m boxed ../../../vault.db",
              "cd ./src && git commit -m boxed ~/.boxed/vault.db", "cd link && ls", "cd ./src && cat ../../../../proj2/.env",
              "cd ./src && ls ../../../../proj2", "cd ./src && grep -r x ../../../vault.db", "cd ./src && git status ../../../../proj2",
              # CDPATH sends a bare name to $HOME/proj2; cd folds .. before it follows rel5 (src/a/b/c/d), so pytest starts in $HOME
              "cd proj2 && git commit -m boxed", "cd src && git commit -m boxed", "cd src && pytest -m boxed", "cd src/.. && git commit -m boxed",
              "cd rel5/../../../.. && pytest -m boxed proj2", "cd ./rel5/../../../.. && git commit -m boxed", "cd rel5/.. && pytest -m boxed",
              "cd ./src/../.. && git commit -m boxed", "cd src/a/../../.. && pytest -m boxed")
# the guard read the paths after a cd from the wrong folder, so these passed: src/link2 is a link out of the mirror that is only a link from src;
# and rel5/../../../.. is $HOME for cd, which the guard took for a folder inside the mirror
CD_HOLES = ("cd src && cat link2/.env", "cd src && ls link2", "cd src && grep -r x link2", "cd src && git status link2/src",
            "cd rel5/../../../.. && cat proj2/.env", "cd ./rel5/../../../.. && ls proj2", "cd rel5/../../../.. && git status proj2")
# patterns the shell turns into names the text does not show: s* is src, and from src the way up leads out of the mirror; li* is a link out
GLOB_HOLES = ("cat s*/../../../../proj2/.env", "cat s?c/../../../../proj2/.env", "cat [s]rc/../../../../proj2/.env", "cat ./s*/../../../../proj2/.env",
              "cat */.env", "ls li*", "ls l?nk", "ls [l]ink", "cat l*/.env", "cat ./l*/.env", "grep -r x lin[k]", "ls src/li*", "cat src/l*2/.env", "cat sec*",
              "cat */../../../vault.db", "ls *", "ls {1..3}", "ls ^zz", "cat **/.env", "ls **/link2", "ls .[h]id", "git -C li* log",
              "ls <->", "ls <1-9>", "cat <->/.env", "eval 'ls li*'", 'bash -c "cat */.env"', "sh -c 'cat s*/../../../../proj2/.env'", "xargs sh -c 'cat sec*' ", "bash -c \"eval 'ls l?nk'\"",
              # a : or = inside a bracket is not a cut between paths
              "git -C .[[*alpha:]* log", "ls .[h:]id", "ls [l:]ink", "ls li[n:]k", "ls [l=]ink", "cat [l:x]ink/.env", "grep -r x {src,x}/li[n[:]]k2")
SEEDS = ARITHMETIC + ATTACKS + ARITH_HOLES + PRINTING + CD + CD_ATTACKS + CD_HOLES + GLOB_HOLES + BRACE_HOLES
INNER = ("6 / 3", "6/3", "6 /3", "6 // 3", "6 / 3 / 1", "6 / $(ls /)", "$(ls /) / 3", "6 / `ls /`", "(6 / 3)", "6 / 3)", "a / 3", "6 / ${HOME}",
         "6 / ~", "6 /\n3", "6 / 3;ls /", "6 / 3 ) ; ls / ; echo $((1", "/", " / ", "6 / 3 + $HOME", "6 / 3 > /")
PREFIXES = ("", "", "", "( ", "{ ", "! ", "time ", "FOO=1 ", "> out ", "2>&1 ", "echo x; ", "true && ", "false || ", "cd .. ; ", "cd src ; ",
            "x=$( ", "eval ", "bash -c ", "exec ", "command ", "builtin ", "env ", "sudo ", "nohup ", "xargs ", "echo $(", "`", "\n",
            "# c\n", ": ", "if true; then ", "for i in 1; do ", "cat <<EOF\n", "ls /\n")
WRAPS = ("§", "§", "§", "(§)", "$(§)", "`§`", "'§'", '"§"', "bash -c '§'", "eval '§'", "{ §; }", "echo §", "echo $(§)", "if true; then §; fi",
         "§ &", "§ | cat", "cat <(§)", "§ >/dev/null", "cat <<EOF\n§\nEOF", "cat <<'EOF'\n§\nEOF", "x=§", "# §", "§ # §", "§\n§")
SUFFIXES = ("", "", "", " # x", " ; ls /", " && ls /", " || ls /", " | cat /", " & ls /", "\nls /", " > out", " > /", " >> ~/.boxed/vault.db",
            " < ~/proj2/.env", " $(ls /)", " `ls /`", " $'/'", ' "/"', " '/'", " \\/", " ~", " $HOME", " ..", " ../..", " /", " /*", " {/,}",
            " ~/*", " *", " ~/.boxed", " ~/proj2", " ~/proj2/.env", " $HOME/proj2", " <<EOF\nbody\nEOF", " \\\n/", " ;", " &", " |", " )", " (",
            " $(", " `", " '", ' "', "\n", "  ", "\t", " -", " --", " -m boxed", " /boxed",
            " li*", " l?nk", " [l]ink", " {link,x}", " l*/.env", " ./l*", " ~/PROJ2", " §H/PROJ2/.env", " §H/.BOXED/vault.db", " ~-", " ~+/..")


def vary(seed, inner, word, prefix, wrap, suffix):
    return prefix + wrap.replace("§", seed.replace("6 / 3", inner).replace("§P", word) + suffix)


variants = st.builds(vary, st.sampled_from(SEEDS), st.sampled_from(INNER), st.sampled_from(ANCESTORS + INSIDE + ODD), st.sampled_from(PREFIXES),
                     st.sampled_from(WRAPS), st.sampled_from(SUFFIXES))

# The structured variants above are mostly blocked by both guards (a prefix, a wrapper and a suffix together seldom leave a plain line) and
# prove nothing then: a few in a hundred reach the shell. This fuzz starts from the lines the allowances are for and changes them a
# character or a word at a time, and a case is drawn again until the old guard blocks it and the guard passes it: every case it
# returns is run for real.
FUZZ_PLAIN = (*"abcxyz019-_.,:=@%+/~ \t", "  ", "src", "link", "7", "proj2", "app.py", "-m", "boxed", "..", "./", "$HOME", "-n 1", "--", "'x'", '"x"')
FUZZ_SPECIAL = ("\\\n", "\\", "'", '"', "$", "$(", "`", "(", ")", "{", "}", ";", "&", "&&", "||", "|", "<", ">", ">>", "<<", "*", "?", "[", "]", "#", "!", "\n", "$'\\x2f'",
                "$((", "))", "\r", "\x00", "<(", ">(", "2>&1", "&>", "<<<", "@", "python3 -m boxed", "li*", "rel5/..", "<->", "$(( 14 / 2 ))", "$(( 6 / 3 ))", "~-", "~+", "§H",
                "§M", "..", "../..", "^", "**/", "$PWD", "${HOME}", "~/.boxed", "\x0c")
ALLOWED_SEEDS = (ARITHMETIC, CD, tuple(seed.replace("§P", word) for seed in PRINTING for word in ANCESTORS))  # one family each


def candidate(rnd):
    """A line near the ones the allowances are for."""
    seed = rnd.choice(rnd.choice(ALLOWED_SEEDS)) if rnd.random() < 0.85 else rnd.choice(SEEDS)
    text = vary(seed, rnd.choice(INNER) if rnd.random() < 0.1 else "6 / 3", rnd.choice(ANCESTORS + INSIDE + ODD), "", "§", "")
    if rnd.random() < 0.1:  # with a prefix, a wrapper, a suffix of the structured vocabulary
        text = vary(seed, "6 / 3", rnd.choice(ANCESTORS + INSIDE), rnd.choice(PREFIXES), rnd.choice(WRAPS), rnd.choice(SUFFIXES))
    for _ in range(rnd.choice((0, 1, 1, 1, 2, 2, 3))):
        at, how = rnd.randint(0, len(text)), rnd.random()
        if how < 0.5:
            text = text[:at] + rnd.choice(FUZZ_PLAIN) + text[at:]
        elif how < 0.8:
            text = text[:at] + rnd.choice(FUZZ_SPECIAL) + text[at:]
        elif how < 0.9:
            text = text[:at] + text[at + rnd.randint(1, 3) :]
        else:
            text = text[:at] + rnd.choice(FUZZ_SPECIAL) + text[rnd.randint(at, len(text)) :]
    return text


def newly_allowed(world, rnd, tries=400):
    """The first candidate the old guard blocks and the guard passes, or None."""
    for _ in range(tries):
        command = world.fill(candidate(rnd))
        if not world.blocks(command) and world.old_blocks(command):
            return command
    return None


def prints_only(line):
    """A second opinion, by scanning instead of matching: one echo, printf or pwd whose words hold, outside single quotes, no expansion
    but $HOME, no group, separator, redirect, glob or brace, and no backslash outside double quotes before a letter or digit."""
    start = re.match(r"(?:echo|printf|pwd)(?=[ \t]|$)", line)
    if not start:
        return False
    rest, quote, i = line[start.end():], None, 0
    while i < len(rest):
        c = rest[i]
        if c == "$" and quote != "'":
            home = re.match(r"\$HOME(?!\w)|\$\{HOME\}", rest[i:])
            if not home:
                return False
            i += home.end() - 1
        elif quote == "'":
            quote = None if c == "'" else quote
            if c in "\n\r\x00":
                return False
        elif quote == '"':
            if c == '"':
                quote = None
            elif c in "`\n\r\x00":
                return False
            elif c == "\\":
                if not rest[i + 1:i + 2].isalnum():
                    return False
                i += 1
        elif c in "'\"":
            quote = c
        elif not (c.isalnum() or c in "_@%+,.:/~- \t"):
            return False
        i += 1
    return quote is None


def intended(world, command):
    """A second opinion on the shape of what the allowances were meant to pass: the family it belongs to, or None."""
    line = command.replace("\\\n", "").strip()  # bash deletes a backslash and its line break before it reads any word
    line = re.sub(r"<\d*-\d*>", "*", line)  # a zsh number range is a wildcard to the guard (and 1<->2 is no arithmetic to zsh: nothing runs)
    if prints_only(line):
        return "print"
    if re.fullmatch(r"expr(?:[ \t]+[0-9]+)(?:[ \t]+[-+/%*\\\\]+[ \t]+[0-9]+)*", line):  # a whole line of expr over numbers
        return "expr"
    unit = r"""(?:[^ \t\n\r;&|<()$`#\\'"]|\$HOME(?!\w)|\$\{HOME\}|'[^'\\]*'|"(?:[^"$`\\\n]|\$HOME(?!\w)|\$\{HOME\})*")"""  # a redirect > file is fine
    cd = re.fullmatch(rf"cd[ \t]+([\w./][\w./-]*)[ \t]*&&[ \t]*(?:git|pytest)(?:[ \t]+{unit}+)*", line)  # two simple commands
    if cd and (cd[1] == "." or cd[1].startswith(("./", "/"))) and ".." not in cd[1].split("/"):  # a path CDPATH and a .. cannot send elsewhere
        return "cd"
    words = re.sub(r"(?<![^ \t])\$\(\([ \t0-9+*/%-]*\)\)(?![^ \t])", "0", line)  # arithmetic words made of numbers and signs
    if words != line and not world.old_blocks(words):  # and nothing else on the line was the reason to block
        return "arithmetic"
    return None


def test_every_seed_is_passed_now_was_blocked_before_and_is_harmless(world):
    for seed in ARITHMETIC + CD:
        seed = world.fill(seed)
        assert world.old_blocks(seed) and not world.blocks(seed), seed
        family = intended(world, seed)
        assert family, seed
        assert world.harm(world.run(seed), family) is None, seed
    for seed in PRINTING:
        for word in ANCESTORS:
            command = world.fill(seed.replace("§P", word))
            assert world.old_blocks(command) and not world.blocks(command), command
            assert intended(world, command) == "print", command
            assert world.harm(world.run(command), "print") is None, command


def test_every_attack_stays_blocked(world):
    for attack in ATTACKS + CD_ATTACKS:
        attack = world.fill(attack)
        assert world.old_blocks(attack) and world.blocks(attack), attack
    for hole in CD_HOLES + GLOB_HOLES + ARITH_HOLES + BRACE_HOLES:
        assert not world.old_blocks(hole) and world.blocks(hole), hole
    for seed in PRINTING:
        for word in INSIDE:
            command = world.fill(seed.replace("§P", word))
            assert world.old_blocks(command) and world.blocks(command), command


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(variants)
@example("expr 6 / 3 ; ls /")
@example("echo $(( 6 / 3 )) /")
@example("ls /\n$(( 6 / 3 ))")
@example("cat <<'EOF'\n$(( 6 / 3 ))\nEOF")
@example("echo '$(( 6 / 3 ))' ; echo $(( 6 / 3 )) ; ls /")
@example("ls $(( 6 / 3 )) \\\n/")
@example("ls $(( 6 / 3 )) $'/'")
@example('ls "§H/proj"$(( 6 / 3 ))')
@example("echo ~ ; ls ~")
@example("echo ~ \\\n~/proj2")
@example("echo ~ > out")
@example("echo $HOME/proj2")
@example("echo ~/*")
@example("cd ./src && git commit -m boxed ../../../../proj2/.env")
@example("cd link && git commit -m boxed")
@example("cd .. && git commit -m boxed")
@example("cd ./src && git commit -m boxed; python3 -m boxed")
@example("cd ./src && cat ../../../../proj2/.env")
@example("cd ./src && git commit -m boxed -- link/.env")
@example("cd rel5/../../../.. && pytest -m boxed proj2")
@example("cd rel5/../../../.. && cat proj2/.env")
@example("cd proj2 && git commit -m boxed")
@example("expr 6 \\\\\n* 3 / 2")
@example("cd . && \rgit commit -m boxed")
@example("echo ~+/../ws-other")
@example("cd . && pytest -m boxed li*")
@example("cd ./src && git commit -m boxed $HOMEx")
@example("ls §H/PROJ2")
@example("ls li*")
@example("echo 'home:' \"../.{ME/.,.\"")
def test_what_the_old_guard_blocked_and_the_guard_passes_is_an_intended_allowance_and_harmless(world, command):
    command = world.fill(command)
    if world.blocks(command) or not world.old_blocks(command):
        return
    family = intended(world, command)
    assert family, command
    assert world.harm(world.run(command), family) is None, command


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.integers(0, 2**32))
def test_a_fuzz_of_the_allowed_lines_is_intended_and_harmless_where_the_old_guard_blocked_and_the_guard_passes(world, seed):
    command = newly_allowed(world, random.Random(seed))
    assume(command is not None)
    family = intended(world, command)
    assert family, command
    assert world.harm(world.run(command), family) is None, command


def test_the_fuzz_runs_hundreds_of_allowed_lines_of_every_family_in_the_shell(world):
    """The point of the fuzz: not one example in thirty but every one of them is run for real, and every allowance is among them."""
    rnd, families = random.Random(20261023), Counter()
    for _ in range(300):
        command = newly_allowed(world, rnd)
        assert command is not None
        family = intended(world, command)
        assert family, command
        why = world.harm(world.run(command), family)
        assert why is None, (command, why)
        families[family] += 1
    assert min(families[name] for name in ("expr", "print", "cd", "arithmetic")) >= 15, families


# ---- wildcards ---------------------------------------------------------------------------------------------------------------------
#
# The guard matches the names of a folder against a pattern itself (hooks._wildcard) and walks the folders the shell would walk. A name too
# few lets a link through, so the matcher is compared with the shells; then whole commands with patterns are run for real.

WILD_NAMES = ("a", "b", "c", "A", "B", "ab", "abc", "ba", "bc", "a-b", "a_b", "a.b", "a b", "5", "55", "a5", "-", "_", "!", "^", "[", "]", "[a]", "a[", "a]", "{",
              "}", "a{b}", "*", "?", "é", "É", "x1y22z", ".a", ".ab", "..a", ".a.b", "...", "app.py", "app.pyc", "Abc", "abC", "ABC", " ", "~", "~a", "#a", "a#",
              "$", "a$b", "%", "&", "(", ")", ";", "|", "<", ">", "'", '"', "\\", "a\tb", "ß", "中")
WILD_PARTS = ("*", "*", "?", "?", "a", "b", "A", ".", "-", "_", "5", "[ab]", "[!a]", "[^a]", "[a-c]", "[]a]", "[!]a]", "[a-]", "[-a]", "[^]a]", "[[:alpha:]]",
              "[[:digit:]]", "[![:digit:]]", "[[:alnum:]_]", "[[:upper:]]", "[[:lower:]]", "[[:space:]]", "[[:punct:]]", "[[:alpha:][:digit:]]", "[a-z-9]",
              "[[:foo:]]", "[z-a]", "é", "[", "]", "{", "}", "[!", "[[", "[]", "[a", "a]", "[A-Z]", "[0-9]", "[%-+]", "[[:xdigit:]]", "[[:blank:]]",
              ":", "[:", ":]", "[:]", "[n[:]]", "[:a]", "[a:]", "[[:]", "[[:]]", "[:alpha]", "[[:alpha:]", "[a[:digit:]]")


@pytest.fixture(scope="module")
def wild_folder(tmp_path_factory):
    folder = tmp_path_factory.mktemp("wild")
    for name in WILD_NAMES:
        (folder / name).write_text("")
    return folder


def shell_matches(shell, folder, patterns, locale="en_US.UTF-8"):
    """What the shell makes of each pattern in the folder: the names it matches (nothing when it leaves the pattern as it is)."""
    name = next(n for n, argv in SHELLS.items() if argv == shell)
    options = "setopt nonomatch\n" if name == "zsh" else ""
    script = options + "".join(f"printf '\\036'; eval 'printf \"%s\\0\" {pattern}' 2>/dev/null\n" for pattern in patterns)
    done = subprocess.run([*shell, script], cwd=folder, env={"PATH": "/usr/bin:/bin", "LC_ALL": locale}, capture_output=True, timeout=30,
                          stdin=subprocess.DEVNULL)
    answers = done.stdout.decode(errors="replace").split("\x1e")[1:]
    assert len(answers) == len(patterns), (shell, patterns[:3])
    found = []
    for pattern, answer in zip(patterns, answers):
        names = [n for n in answer.split("\0") if n != ""]
        found.append([] if names == [pattern] and pattern not in WILD_NAMES else names)
    return found


@pytest.mark.parametrize("shell", [pytest.param(argv, id=name, marks=pytest.mark.skipif(not os.path.exists(argv[0]), reason=f"needs {name}"))
                                   for name, argv in SHELLS.items()])
@pytest.mark.parametrize("locale", ["en_US.UTF-8", "C"])  # in C a shell counts the bytes of a name: ?? stands for é
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(st.lists(st.sampled_from(WILD_PARTS), min_size=1, max_size=4).map("".join), min_size=15, max_size=15))
@example(["[a-z-9]", "[[:foo:]]", "[z-a]", "[!]a]*", "{*}", "[]a]", "*[", "[[:alpha:]]*", "a{b}", "[ab", "?[", "[^]a]", "[%-+]", "[a-]", "[-a]"])
@example(["??", "?", "???", "[é]", "é?", "?é", "*é", "[!a]", "[[:alpha:]]", "[[:alpha:]][[:alpha:]]", "?*?", "é", "[ß]?", "?[中]", "????", "[!é]", "*"])
def test_the_wildcard_matcher_matches_every_name_the_shell_matches(shell, locale, wild_folder, patterns):
    for pattern, names in zip(patterns, shell_matches(shell, wild_folder, patterns, locale)):
        for name in names:
            assert hooks._wildcard(pattern).fullmatch(name), (shell[0], locale, pattern, name)


GLOB_COMPONENTS = ("src", "s*", "s?c", "[s]rc", "*", "*", "l*", "li?k", "link", "link2", "rel5", "r*", "..", "..", ".", "a", "b", "c", "d", "proj2", "p*", ".env",
                   "*.py", "app.py", "{src,link}", "**", ".*", ".[!.]*", "[!x]*", "[[:lower:]]*", "^x", "secret", "sec*", ".hid", ".h*", "???", "?*", "s*c", "[a-d]", "[l:]*", ".[h:]*", "li[n:=]k", "a{", "{a", "a{/..", ".{ME")
GLOB_LEADS = ("", "", "./", "src/", "src/", "./src/", "§M/", "§M/src/", "src/a/", "rel5/", "../")
GLOB_COMMANDS = ("cat {}", "ls {}", "head -n1 {}", "git -C {} log", "grep -r x {}", "wc -l {}", "cat {} {}", "git diff --no-index {} {}")


# paths that exist in the world, and what can be put after them
REAL_PATHS = ("src", "src/app.py", "src/link2", "src/link2/.env", "src/link2/src/app.py", "link", "link/.env", "link/src", "link/src/app.py", "rel5", "secret",
              ".hid", ".hid/.env", "src/a/b/c/d", ".claude", ".env", "src/a", "src/a/b", "rel5/../..", "src/a/b/../..", "a{", "a{/..")
TAILS = ("", "", "", "/..", "/../..", "/../../..", "/../../../..", "/../../../../proj2/.env", "/../../../vault.db")


def generalized(path, rnd):
    """A real path of the world with some of its names turned into patterns."""
    parts = path.split("/")
    for _ in range(rnd.randint(1, 3)):
        i = rnd.randrange(len(parts))
        part = parts[i]
        if part in ("", ".", ".."):
            continue
        k = rnd.randrange(len(part))
        parts[i] = rnd.choice((part[:k] + "*", "*" + part[k:], part[:k] + "?" + part[k + 1 :], part[:k] + "[" + part[k] + "]" + part[k + 1 :], "*",
                               part[:k] + "*" + part[k + 1 :], "{" + part + ",x}", part[:k] + "[!x]" + part[k + 1 :], part[:k] + "[[:alpha:]]" + part[k + 1 :],
                               part[:k] + "[" + part[k] + ":]" + part[k + 1 :], part[:k] + "[" + part[k] + "=x]" + part[k + 1 :]))
    return "/".join(parts)


def glob_command(rnd):
    if rnd.random() < 0.3:
        path = rnd.choice(GLOB_LEADS) + "/".join(rnd.choice(GLOB_COMPONENTS) for _ in range(rnd.randint(1, 5)))
    else:
        path = rnd.choice(("", "", "./", "§M/")) + generalized(rnd.choice(REAL_PATHS), rnd) + rnd.choice(TAILS)
    return rnd.choice(GLOB_COMMANDS).format(path, path)


def test_a_command_with_a_pattern_that_the_guard_passes_reaches_no_protected_data(world):
    """Random patterns in the world, where links lead out of the mirror: whatever the guard passes, the shell must not turn into a path that
    reaches protected data. The patterns are real paths of the world with names turned into wildcards, and some random ones; most are blocked
    and the test insists on passes that really ran and some of those that the shell really expanded."""
    import random

    rnd, ran, expanded, harmful = random.Random(20261023), 0, 0, []
    for _ in range(2500):
        command = world.fill(glob_command(rnd))
        if world.blocks(command):
            continue
        ran += 1
        run = world.run(command)
        literal = command.split(" ", 1)[1].split(" log")[0]
        expanded += any(literal not in args for _, _, args in run.externals)
        why = world.harm(run, "glob")
        if why:
            harmful.append((command, why))
    assert not harmful, harmful[:5]
    assert ran >= 400 and expanded >= 80, (ran, expanded)


# ---- text written into a file (Write, Edit, MultiEdit, NotebookEdit) ------------------------------------------------------------
#
# A script that runs boxed when bash runs it must be refused as text. The forms below are the ones the check is meant to see: boxed (or
# a module run) as a command, behind a wrapper, a separator or a group, with its name split by quotes or a line continuation. Names
# built at run time ($(echo bo)xed), wrappers the check does not list and the like are the known limits, not generated here.

BOXED_RUNS = ("boxed restore --scope x", "boxed mask f", "boxed workspace list", "boxed journal show", "boxed restore-file a b", "boxed mask-file a b",
              "python3 -m boxed.cli restore", "python3 -m boxed", "python3 -Im boxed", "uv run -m boxed", "uv run --module boxed.cli", "python -mboxed")
SCRIPT_WRAPS = ("§", "§", "sudo §", "env X=1 §", "nohup §", "time §", "command §", "exec §", "xargs §", "echo hi && §", "true || §", "ls; §",
                "cat f | §", "x=$(§)", "echo $(§)", "(§)", "{ §; }", "if true; then §; fi", "for i in 1; do §; done", "§ &", "! §", "   §",
                "\t§", "eval '§'", "timeout 5 §", "while true; do §; break; done", "echo hi; (§)", "cat <<EOF >/dev/null\nbody\nEOF\n§",
                "case x in x) § ;; esac", "x=`§`", "sh -ec '§'")
DISGUISES = ("boxed", "boxed", "boxed", "bo''xed", 'bo""xed', "b\\oxed", "bo\\\nxed", "'boxed'", '"boxed"', "b\"o\"xed")
SCRIPT_BEFORE = ("", "", "#!/bin/sh\n", "# a comment\n", "set -e\n", "echo start\n", "\n\n", "x=1\n")
SCRIPT_AFTER = ("", "", "\necho done", "\n# end", "\nexit 0", "\n")


def disguised(run, disguise):
    return run.replace("boxed", disguise, 1)


scripts = st.builds(lambda before, wrap, run, disguise, after: before + wrap.replace("§", disguised(run, disguise)) + after,
                    st.sampled_from(SCRIPT_BEFORE), st.sampled_from(SCRIPT_WRAPS), st.sampled_from(BOXED_RUNS), st.sampled_from(DISGUISES),
                    st.sampled_from(SCRIPT_AFTER))


def test_every_listed_form_of_running_boxed_is_refused_as_text():
    forms = itertools.product(SCRIPT_WRAPS[1:], BOXED_RUNS, DISGUISES)
    for i, (wrap, run, disguise) in enumerate(forms):  # the lines around it take turns
        text = SCRIPT_BEFORE[i % len(SCRIPT_BEFORE)] + wrap.replace("§", disguised(run, disguise)) + SCRIPT_AFTER[i % len(SCRIPT_AFTER)]
        assert hooks._writes_boxed(text), text
        if "\\\n" not in text:  # a backslash before a CR is no line continuation
            assert hooks._writes_boxed(text.replace("\n", "\r\n")), text


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(scripts)
@example("boxed restore")
@example("sudo boxed mask f")
@example("python3 -m boxed.cli restore\n")
@example("true && bo''xed restore --scope x\n")
@example("x=$(boxed workspace list)\n")
@example("cat <<EOF >/dev/null\nbody\nEOF\nboxed restore")
def test_a_script_that_bash_runs_as_boxed_is_refused_as_text(world, text):
    if world.run_script(text).modules:
        assert hooks._writes_boxed(text), text


@settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(scripts, st.integers(0, 10_000), st.integers(0, 10_000))
@example("boxed restore", 3, 3)
@example("sudo boxed mask f", 5, 11)
@example("python3 -m boxed.cli restore\n", 10, 12)
def test_a_script_that_bash_runs_as_boxed_is_refused_when_it_is_written_in_steps(world, text, one, two):
    """The text is written with marks in it and the marks are then taken out by an edit: no piece runs boxed, the file the edit leaves does."""
    if not world.run_script(text).modules:
        return
    cuts = sorted({one % (len(text) + 1), two % (len(text) + 1)})
    marks = [f"@@{n}@@" for n in range(len(cuts))]
    first = "".join(piece + (marks[n] if n < len(marks) else "") for n, piece in enumerate(text[a:b] for a, b in zip([0, *cuts], [*cuts, len(text)])))
    path = f"steps/s{next(world.counter)}.sh"
    if world.file_call("Write", file_path=path, content=first) == 2:
        return  # the marks hid nothing: it was refused as it was written
    (world.mirror / "steps").mkdir(exist_ok=True)
    (world.mirror / path).write_text(first)
    edits = [{"old_string": mark, "new_string": ""} for mark in marks]
    assert world.file_call("MultiEdit", file_path=path, edits=edits) == 2, (first, marks)
    if len(edits) == 1:
        assert world.file_call("Edit", file_path=path, **edits[0]) == 2, (first, marks)


# Python that imports the package is read by the guard as text: an import at the start of a statement, a dynamic import. A package called
# boxed that only notes it was imported stands in for the real one, and Python itself says whether a file imports it.
IMPORT_RUNS = itertools.count()
FAKE_BOXED = {"boxed/__init__.py": "import os\nopen(os.environ['IMPORTED'], 'a').write('x')\n", "boxed/cli.py": "main = other = None\n", "boxed/mask.py": "x = None\n"}
IMPORT_STATEMENTS = ("import boxed", "import boxed.cli", "import os, boxed", "import os, sys, boxed.mask as m", "import boxed as b", "from boxed import cli",
                     "from boxed.cli import main", "from boxed import *", "from boxed.cli import (main,\n    other)", "import os,\\\n  boxed", "import os; import boxed",
                     "from boxed.mask import x as y", "import   boxed", "from boxed . cli import main", "from boxed import cli, mask", "import boxed.cli as c, os",
                     'exec("import boxed")', "exec('from boxed import cli')", '__import__("boxed")', "__import__('boxed.cli')",
                     "import importlib; importlib.import_module('boxed.cli')", 'import runpy; runpy.run_module("boxed.cli")', "import importlib as i; i.import_module(\"boxed\")")
IMPORT_WRAPS = ("{}", "if True:\n    {}", "try:\n    {}\nexcept ImportError:\n    pass", "def f():\n    {}\nf()", "class A:\n    {}", "with open(__file__):\n    {}",
                "for _ in [1]:\n    {}", "while True:\n    {}\n    break", "if True: {}", "x = 1; {}", "try: {}\nexcept ImportError: pass", "if False:\n    pass\nelse:\n    {}",
                "assert True; {}", "def f():\n    '''doc'''\n    {}\nf()", "if True:\n\t{}", "async def f():\n    {}\nimport asyncio; asyncio.run(f())", "x = [1]\n{}\ny = 2",
                "if True:\n  {}\n  y = 1", "match 1:\n    case 1:\n        {}")
IMPORT_BEFORE = ("", "", "# note: import boxed later\n", '"""docs\nimport boxed\n"""\n', "import os\n", "\n\n", "x = 1\n", "#!/usr/bin/env python3\n")


@pytest.fixture(scope="module")
def fake_boxed(tmp_path_factory):
    root = tmp_path_factory.mktemp("fakeboxed")
    for name, text in FAKE_BOXED.items():
        (root / name).parent.mkdir(exist_ok=True)
        (root / name).write_text(text)
    return root


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.sampled_from(IMPORT_WRAPS), st.sampled_from(IMPORT_STATEMENTS), st.sampled_from(IMPORT_BEFORE))
@example("{}", "import boxed", "")
@example("if True: {}", "import boxed", "")
@example("{}", "from boxed.cli import (main,\n    other)", "")
def test_python_that_really_imports_the_package_is_refused_as_text(fake_boxed, wrap, statement, before):
    text = before + wrap.format(statement) + "\n"
    marker = fake_boxed / f"imported{next(IMPORT_RUNS)}"
    script = fake_boxed / "script.py"
    script.write_text(text)
    subprocess.run([sys.executable, "-S", "-s", str(script)], cwd=fake_boxed, env={"IMPORTED": str(marker), "PATH": os.defpath}, capture_output=True,
                          timeout=30, stdin=subprocess.DEVNULL)
    if marker.exists():
        for kind in ("python", "script", "both"):
            assert hooks._writes_boxed(text, kind), (kind, text)
        marker.unlink()  # a file that imports nothing, or does not run, may be refused or not
