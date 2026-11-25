"""The text of an error that the person sees is built from fixed words. cli.main prints the message of errors.UserError and its
subclasses and of nothing else, so every call that makes one is read here from the source: its arguments may hold string constants,
module constants, items of a constant table, the helpers of boxed.errors (one_of, number), min, max, len and sorted of those, and
", ".join of those. A local variable, an attribute of an object, str(e) or a path is refused: it could carry a value.

A module constant is a name the module assigns at its top level (or imports from a module of the package that does), and only to
fixed words: a string or a number, a tuple, list, set or dict of those, or a comprehension over such a collection whose items are
fixed words again. Its case proves nothing: a name in UPPER_CASE that a function assigns is a local variable, and a table with one
computed value is no constant table."""

import ast
import functools
from pathlib import Path

import pytest

import boxed

SRC = Path(boxed.__file__).parent
HELPERS = frozenset({"one_of", "min", "max", "len", "sorted"})
# errors.number takes an int and nothing else (a text of digits is refused), so what it is given may be any expression.
COUNTED = "number"
# Functions that build a safe error from their first argument and fixed words: their own bodies are not read, every call of them
# is, as a call of the class would be, all but the first argument.
BUILDERS = {
    "_bad": "the first argument is a number the code counted, which the builder passes to errors.number",
    "_fail": "the first argument is a provider of channels.PROVIDERS, a closed set: channels._fail writes its name only",
}
# Calls a module constant may be built with: what they make of fixed words is fixed words.
CONSTANT_CALLS = frozenset({"frozenset", "tuple", "set", "list", "dict", "sorted", "min", "max", "len", "one_of"})
CONSTANT_METHODS = frozenset({"join", "split", "items", "keys", "values", "upper", "lower"})
BUILTIN_TYPES = frozenset({"str", "int", "float", "bool", "list", "dict", "tuple", "set"})  # their names are fixed words


@functools.cache
def _package() -> dict[Path, ast.Module]:
    return {path: ast.parse(path.read_text(encoding="utf-8"), str(path)) for path in sorted(SRC.rglob("*.py"))}


def _trees() -> dict[Path, ast.Module]:
    return dict(_package())


def _base_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "ctypes":
        return None  # ctypes.FormatError: the text of a Windows error number, not the class of boxed
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None


def safe_classes(trees) -> set[str]:
    """UserError and every class of the package that derives from it, found by name."""
    bases = {
        node.name: {_base_name(base) for base in node.bases}
        for tree in trees.values()
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    }
    safe, grown = {"UserError"}, True
    while grown:
        grown = False
        for name, of in bases.items():
            if name not in safe and of & safe:
                safe.add(name)
                grown = True
    return safe


def _module_path(trees, here: Path, level: int, module: str | None) -> Path | None:
    """The file of the package that `from <level dots><module> import ...` in `here` names, or None outside the package."""
    if level:
        base = here.parent
        for _ in range(level - 1):
            base = base.parent
        parts = module.split(".") if module else []
    else:
        if not module or not (module == "boxed" or module.startswith("boxed.")):
            return None
        base, parts = SRC, module.split(".")[1:]
    target = base.joinpath(*parts)
    for candidate in (target.with_suffix(".py") if parts else None, target / "__init__.py"):
        if candidate is not None and candidate in trees:
            return candidate
    return None


class Reader:
    """What the package's modules assign at their top level and import, to judge the names an error text uses."""

    def __init__(self, trees):
        self.trees = trees
        self.assigned: dict[Path, dict[str, list[ast.expr]]] = {}
        self.imported: dict[Path, dict[str, tuple[Path, str | None]]] = {}  # name -> (module, its name there; None: the module)
        for path, tree in trees.items():
            assigned: dict[str, list[ast.expr]] = {}
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assigned.setdefault(target.id, []).append(node.value)
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                    assigned.setdefault(node.target.id, []).append(node.value)
            self.assigned[path] = assigned
            imported: dict[str, tuple[Path, str | None]] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    source = _module_path(trees, path, node.level, node.module)
                    for alias in node.names:
                        sub = _module_path(trees, path, node.level, f"{node.module}.{alias.name}" if node.module else alias.name)
                        if sub is not None:
                            imported[alias.asname or alias.name] = (sub, None)
                        elif source is not None:
                            imported[alias.asname or alias.name] = (source, alias.name)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        source = _module_path(trees, path, 0, alias.name)
                        if source is not None and alias.asname:
                            imported[alias.asname] = (source, None)
            self.imported[path] = imported
        self._known: dict[tuple[Path, str, bool], bool] = {}

    def constant(self, path: Path, name: str, keys: bool = False, depth: int = 0) -> bool:
        """Is `name`, as the module at `path` knows it, a module constant? `keys`: only what iterating it gives counts (the keys of
        a dict: one_of, sorted, min, max and len read nothing else)."""
        key = (path, name, keys)
        if key in self._known:
            return self._known[key]
        self._known[key] = False  # a name defined by itself is not a constant
        if name in self.assigned[path]:
            found = all(self.value(path, node, frozenset(), keys) for node in self.assigned[path][name])
        elif name in self.imported[path] and depth < 8:
            source, there = self.imported[path][name]
            found = there is not None and self.constant(source, there, keys, depth + 1)
        else:
            found = False
        self._known[key] = found
        return found

    def module(self, path: Path, node: ast.expr) -> Path | None:
        """The module of the package a name stands for, as `channels` in channels._KEY_REFUSAL."""
        if isinstance(node, ast.Name) and node.id in self.imported[path]:
            source, there = self.imported[path][node.id]
            return source if there is None else None
        return None

    def value(self, path: Path, node: ast.expr, bound: frozenset[str], keys: bool = False) -> bool:
        """Is the expression of a module-level assignment made of fixed words only? `bound`: the names of a comprehension, each an
        item of a collection already judged."""
        if isinstance(node, ast.Constant):
            return node.value is None or isinstance(node.value, (str, int))  # a bool too: a key of a table
        if isinstance(node, ast.Name):
            return node.id in bound or node.id in BUILTIN_TYPES or self.constant(path, node.id, keys)
        if isinstance(node, ast.Attribute):
            if node.attr == "__name__":  # of a builtin type, or of a name bound to one
                return self.value(path, node.value, bound)
            source = self.module(path, node.value)
            return source is not None and self.constant(source, node.attr, keys)
        if isinstance(node, ast.JoinedStr):
            return all(
                isinstance(part, ast.Constant) or (isinstance(part, ast.FormattedValue) and self.value(path, part.value, bound))
                for part in node.values
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.BitOr, ast.BitAnd)):
            return self.value(path, node.left, bound, keys) and self.value(path, node.right, bound, keys)
        if isinstance(node, ast.IfExp):
            return self.value(path, node.body, bound, keys) and self.value(path, node.orelse, bound, keys)
        if isinstance(node, ast.Starred):
            return self.value(path, node.value, bound, keys)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return all(self.value(path, item, bound) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(
                (self.value(path, k, bound) if k is not None else self.value(path, v, bound, keys))
                and (keys or k is None or self.value(path, v, bound))
                for k, v in zip(node.keys, node.values, strict=True)
            )
        if isinstance(node, ast.Subscript):  # an item of a constant table
            return self.value(path, node.value, bound)
        if isinstance(node, ast.Call):
            args = [*node.args, *(keyword.value for keyword in node.keywords)]
            if isinstance(node.func, ast.Name) and node.func.id in CONSTANT_CALLS:  # each reads what iterating its argument gives
                return all(self.value(path, arg, bound, keys=node.func.id != "dict") for arg in args)
            if isinstance(node.func, ast.Attribute) and node.func.attr in CONSTANT_METHODS:
                over = node.func.attr in ("join", "keys")  # what iterating the collection gives: the keys of a dict
                return self.value(path, node.func.value, bound, over) and all(self.value(path, arg, bound, over) for arg in args)
            return False
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            names = set(bound)
            for generator in node.generators:
                if not self.value(path, generator.iter, frozenset(names), keys=True):  # a loop over a dict gives its keys
                    return False
                names |= {n.id for n in ast.walk(generator.target) if isinstance(n, ast.Name)}
            inner = frozenset(names)
            if isinstance(node, ast.DictComp):
                return self.value(path, node.key, inner) and (keys or self.value(path, node.value, inner))
            return self.value(path, node.elt, inner)
        return False

    def fixed(self, path: Path, node: ast.expr, local: frozenset[str] = frozenset()) -> bool:
        """Is the argument of an error made of fixed words and closed sets only? `local`: the names the enclosing functions bind."""
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, int)) and not isinstance(node.value, bool)
        if isinstance(node, ast.Name):
            return node.id not in local and self.constant(path, node.id)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in local:
                return False
            source = self.module(path, node.value)
            return source is not None and self.constant(source, node.attr)
        if isinstance(node, ast.JoinedStr):
            return all(
                isinstance(part, ast.Constant)
                or (isinstance(part, ast.FormattedValue) and self.fixed(path, part.value, local)
                    and (part.format_spec is None or self.fixed(path, part.format_spec, local)))
                for part in node.values
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            return self.fixed(path, node.left, local) and self.fixed(path, node.right, local)
        if isinstance(node, ast.Subscript):  # an item of a constant table: the table decides what can come out
            return self.fixed(path, node.value, local)
        if isinstance(node, ast.IfExp):
            return self.fixed(path, node.body, local) and self.fixed(path, node.orelse, local)
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(self.fixed(path, item, local) for item in node.elts)
        if isinstance(node, ast.Call):
            args = [*node.args, *(keyword.value for keyword in node.keywords)]
            if isinstance(node.func, ast.Name) and node.func.id == COUNTED:
                return True
            if isinstance(node.func, ast.Name) and node.func.id in HELPERS:
                return all(self._collection(path, arg, local) for arg in args)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and isinstance(node.func.value, ast.Constant):
                return all(self._collection(path, arg, local) for arg in args)
        return False

    def _collection(self, path: Path, node: ast.expr, local: frozenset[str]) -> bool:
        """An argument of one_of, sorted, min, max, len or join: what iterating it gives (the keys of a dict) is fixed words."""
        if isinstance(node, ast.Name) and node.id not in local:
            return self.constant(path, node.id, keys=True)
        if isinstance(node, ast.Attribute) and (source := self.module(path, node.value)) is not None:
            return self.constant(source, node.attr, keys=True)
        return self.fixed(path, node, local)


def _bound(function: ast.AST) -> set[str]:
    """The names a function binds itself: its arguments and every name it assigns, loops over, catches or defines."""
    names = set()
    if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = function.args
        names |= {a.arg for a in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs, arguments.vararg, arguments.kwarg] if a}
    for node in ast.walk(function):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not function:
            names.add(node.name)
    return names


def _calls(node: ast.AST, local: frozenset[str] = frozenset()):
    """Every call with the names its enclosing functions bind; the bodies of the builders are left out."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name in BUILDERS:
            continue
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            yield from _calls(child, local | _bound(child))
            continue
        if isinstance(child, ast.Call):
            yield child, local
        yield from _calls(child, local)


def unsafe_calls(tree: ast.Module, safe: set[str], reader: Reader | None = None, path: Path | None = None) -> list[int]:
    """The lines of the calls of a safe class or a builder with an argument that is not fixed."""
    if reader is None:
        path = SRC / "_snippet.py"
        reader = Reader({**_package(), path: tree})
    found = []
    for node, local in _calls(tree):
        name = _base_name(node.func)
        if name not in safe | BUILDERS.keys():
            continue
        args = node.args[1:] if name in BUILDERS else node.args  # see BUILDERS for what the first argument is
        if not all(reader.fixed(path, arg, local) for arg in [*args, *(keyword.value for keyword in node.keywords)]):
            found.append(node.lineno)
    return found


def test_every_safe_error_is_built_from_fixed_words():
    trees = _trees()
    safe = safe_classes(trees)
    assert {"UserError", "FormatError", "PlanError", "PolicyError", "RecordError", "ChannelError"} <= safe
    assert {"skills", "audit"} <= {path.relative_to(SRC).parts[0] for path in trees}  # the whole package is read, these folders too
    reader = Reader(trees)
    bad = {str(path.relative_to(SRC)): lines for path, tree in trees.items() if (lines := unsafe_calls(tree, safe, reader, path))}
    assert bad == {}


def test_the_safe_errors_are_raised_in_many_places():
    """Not a check that reads nothing: the commands raise these errors in many places."""
    trees = _trees()
    safe = safe_classes(trees)
    calls = sum(
        1
        for tree in trees.values()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _base_name(node.func) in safe | BUILDERS.keys()
    )
    assert calls >= 100


def test_the_errors_whose_text_cli_prints_are_all_read_here():
    """_error_text prints str() of UserError only; the vault and the journal get fixed words of cli, whatever their message."""
    source = (SRC / "cli.py").read_text(encoding="utf-8")
    function = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == "_error_text")
    printed = {
        _base_name(branch.test.args[1])
        for branch in ast.walk(function)
        if isinstance(branch, ast.If) and isinstance(branch.test, ast.Call) and _base_name(branch.test.func) == "isinstance"
        and any(isinstance(n, ast.Return) and isinstance(n.value, ast.Call) and _base_name(n.value.func) == "str" for n in branch.body)
    }
    assert printed <= safe_classes(_trees())


@pytest.mark.parametrize(
    "source",
    [
        "raise UserError(f'{path}: not UTF-8')",
        "raise UserError('unknown scope ' + scope)",
        "raise UserError(str(error))",
        "raise FormatError(f'cannot read {name!r}')",
        "raise PolicyError(f'{category}:{kind}: looser')",
        "raise UserError(f'{args.action} needs a folder')",
        "raise _bad(n, what)",
        "raise _bad(n, f'step {column}')",
        "raise UserError(', '.join(unknown))",
        "raise _fail(provider, what)",
        "raise _fail(spec, f'HTTP {code}')",
        "def f(value):\n    MESSAGE = value\n    raise UserError(MESSAGE)",  # a local variable in UPPER_CASE
        "raise UserError(NOT_DEFINED_ANYWHERE)",
        "raise UserError(TABLE[key])\nTABLE = {'a': 'fixed', 'b': str(open('x'))}",  # a table with a computed value
        "raise UserError(TABLE[key])\nTABLE = {k: v for k, v in os.environ.items()}",
        "raise UserError(NAMES)\nNAMES = read_names()",
        "def f(x):\n    for NAME in x:\n        raise UserError(NAME)\nNAME = 'fixed'",  # the local shadows the constant
    ],
)
def test_the_check_refuses_a_value_in_the_text(source):
    tree = ast.parse("class FormatError(UserError): pass\nclass PolicyError(FormatError): pass\n" + source)
    lines = unsafe_calls(tree, safe_classes({Path("x.py"): tree}))
    assert len(lines) == 1 and lines[0] >= 3


@pytest.mark.parametrize(
    "source",
    [
        "raise UserError('the input is not UTF-8')",
        "KEYCHAIN_MISSING = 'no keychain'\nraise UserError(KEYCHAIN_MISSING)",
        "from .detect import KINDS_BY_LEVEL\nraise UserError(f'level must be {min(KINDS_BY_LEVEL)} to 3')",
        "from .policy import VERDICTS\nraise UserError(f'expected one of {one_of(VERDICTS)}')",
        "from .config import TYPE_ERRORS\nraise UserError(TYPE_ERRORS[key])",
        "from . import channels\nraise UserError(channels._KEY_REFUSAL)",
        "raise UserError(f'row {number(n)} is too long')",
        "raise _bad(n, 'unknown column')",
        "raise _fail(spec, 'timed out')",
        "WORDS = ('a', 'b')\nraise _fail(spec, f'HTTP {number(code)} ({WORDS[i]})')",
        "TABLE = {k: f'{k} is missing' for k in ('a', 'b')}\nraise UserError(TABLE[key])",
    ],
)
def test_the_check_lets_fixed_words_through(source):
    tree = ast.parse(source)
    assert unsafe_calls(tree, {"UserError"}) == []
