#!/usr/bin/env python3
"""Run a command and append its CPU time to a file.

Writes "<label> <user_s> <sys_s>" from wait4() rusage (microsecond
precision, all threads), then exits with the command's status.

Usage: cputime.py OUTFILE LABEL CMD [ARGS...]
"""

import os
import subprocess
import sys

out, label, cmd = sys.argv[1], sys.argv[2], sys.argv[3:]
child = subprocess.Popen(cmd)
_, status, usage = os.wait4(child.pid, 0)
child.returncode = os.waitstatus_to_exitcode(status)
with open(out, "a") as f:
    f.write(f"{label} {usage.ru_utime:.6f} {usage.ru_stime:.6f}\n")
sys.exit(child.returncode)
