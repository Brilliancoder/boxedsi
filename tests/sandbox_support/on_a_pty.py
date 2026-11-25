"""Runs a command with a terminal of its own and prints what it wrote, for the sandbox tests.

    on_a_pty.py COMMAND [ARG...]   runs the command with a new pty as its controlling terminal and prints its output
    on_a_pty.py --probe            what the command is: tries to type into its terminal (TIOCSTI), the way a program that waits for
                                   the person's shell to read the characters when it ends would, and reads back what it typed

Under `boxed run` the agent shares the terminal of the person's shell. A program that can type into that terminal gets its characters
run by the shell, outside the sandbox, as soon as the agent ends."""

import fcntl
import os
import pty
import select
import sys
import termios
import time
import tty


def probe() -> None:
    old = termios.tcgetattr(0)
    tty.setraw(0)
    result = {}
    try:
        try:
            for char in b"echo INJECTED\n":
                fcntl.ioctl(0, termios.TIOCSTI, bytes([char]))
            result["typed"] = True
        except OSError as e:
            result["typed"] = False
            result["error"] = os.strerror(e.errno)
        got = b""
        while select.select([0], [], [], 0.5)[0]:
            got += os.read(0, 100)
            if len(got) >= 14:
                break
        result["read back"] = got.decode(errors="replace")
    finally:
        termios.tcsetattr(0, termios.TCSADRAIN, old)
    sys.stdout.write("RESULT " + repr(result) + "\r\n")
    sys.stdout.flush()


def run(command: list[str]) -> None:
    pid, master = pty.fork()  # the child gets the pty as its controlling terminal
    if pid == 0:
        os.execvp(command[0], command)
    seen = b""
    end = time.time() + 60
    while time.time() < end:
        if select.select([master], [], [], 0.5)[0]:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            seen += data
        elif os.waitpid(pid, os.WNOHANG)[0]:
            break
    sys.stdout.write(seen.decode(errors="replace"))


if sys.argv[1:] == ["--probe"]:
    probe()
else:
    run(sys.argv[1:])
