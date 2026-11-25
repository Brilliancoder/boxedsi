"""The errors whose text the person sees.

cli.main prints the message of a UserError (and of its subclasses: FormatError, PlanError, PolicyError, ChannelError) and of nothing else: any
other error shows its class and fixed words, because Python and the libraries quote what they were given (a path, a value, a byte).
So a UserError is built only from fixed words and values of closed sets that the code names itself: the name of a known option, a
format of a fixed list, a number the code counted. Never a path, a value, a key, a scope, a setting or anything read from a file.
tests/test_error_texts.py reads every raise of these classes in the source and fails on any other part; the helpers below are the
only calls it lets through."""


class UserError(ValueError):
    """An error addressed to the person, in fixed words. A ValueError, so the code that catches those keeps working."""


def one_of(names) -> str:
    """A closed set of the code, as "a, b, c"."""
    return ", ".join(names)


def number(value: int) -> str:
    """A count or a position the code made (a step of a plan, a size). An int only: a text of digits may be a PIN."""
    if type(value) is not int:
        raise TypeError("number takes an int")
    return str(value)
