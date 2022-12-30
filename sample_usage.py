from exit_safe_popen import ExitSafePopen
from subprocess import PIPE

with ExitSafePopen() as pipe:
    pipe.Popen(["py", "echo.py"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = pipe.communicate(b"HELLO WORLD")
    print(output.decode())