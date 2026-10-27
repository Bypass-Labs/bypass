"""Exercise curl-style piped stdin with a real terminal and a fixture Muse host."""
import json
import fcntl
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import sys
import struct
import tempfile
import termios
import time

root = Path(__file__).resolve().parent.parent
node = sys.argv[1]
for mode, answer in (("piped", "y"), ("piped", "n"), ("direct", "y"), ("piped", "\x03")):
    with tempfile.TemporaryDirectory(prefix="bypass-terminal-") as temporary:
        base = Path(temporary)
        app = base / "customer app & Ω"
        app.mkdir()
        fake = base / "bin"
        fake.mkdir()
        launched = base / "launch.json"
        approvals = base / "approvals.json"
        host = fake / "muse"
        host.write_text("#!" + sys.executable + "\n" + """
import json,os,sys,selectors,termios,tty,time
from pathlib import Path
assert all(os.isatty(fd) for fd in (0,1,2)), 'Muse must inherit a terminal'
saved=termios.tcgetattr(0)
try:
    tty.setraw(0)
    with selectors.DefaultSelector() as selector:
        selector.register(0,selectors.EVENT_READ)
        os.write(1,b'MUSE_INPUT_READY')
        received=b''
        deadline=time.monotonic()+5
        while not received.endswith(b'\\n'):
            assert selector.select(max(0,deadline-time.monotonic())), 'Terminal input was not delivered to Muse'
            chunk=os.read(0,4096)
            assert chunk, 'Terminal input closed'
            received+=chunk
        assert received==b'bypass-input\\n', repr(received)
    Path(LAUNCHED).write_text(json.dumps({'cwd':os.getcwd(),'args':sys.argv[1:],'input':received.decode()}))
finally:
    termios.tcsetattr(0,termios.TCSANOW,saved)
""".replace("LAUNCHED",repr(str(launched))))
        host.chmod(0o755)
        driver = base / "setup.mjs"
        driver.write_text("""
import fs from 'node:fs';
import {setupTerminal,finishMuseSetup} from MODULE;
const value={valid:true,active:true,record:{package_sha256:'fixture',cache_path:'fixture'},runtime_capabilities:['hook:session-context','mcp_server:security'].map(id=>({candidate:{stable_id:'plugin:bypass:'+id},status:'review_needed'}))};
const terminal=setupTerminal();
if(!terminal)throw new Error('Piped installer did not find its controlling terminal');
try{
 const result=await finishMuseSetup({cwd:process.cwd(),inspect:async()=>structuredClone(value),approve:async id=>{value.runtime_capabilities.find(row=>row.candidate.stable_id===id).status='trusted_enabled';fs.writeFileSync(APPROVALS,JSON.stringify(value.runtime_capabilities));},ask:terminal.ask,launch:terminal.launch});
 process.exitCode=result.exitCode??0;
}finally{terminal.close();}
""".replace("MODULE", json.dumps((root / "src/muse-setup.mjs").as_uri()))
           .replace("APPROVALS", json.dumps(str(approvals))))
        bootstrap = base / "install.sh"
        bootstrap.write_text(shlex.quote(node) + " " + shlex.quote(str(driver)) + "\n")
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(app)
            env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ["PATH"], TERM="xterm-256color")
            env.pop("CI", None)
            env.pop("BYPASS_NO_OPEN_MUSE", None)
            command = "cat " + shlex.quote(str(bootstrap)) + " | bash" if mode == "piped" else "bash " + shlex.quote(str(bootstrap))
            os.execve("/bin/bash", ["bash", "-c", command], env)
        fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',40,120,0,0))
        transcript = b""
        sent = False
        input_sent = False
        status = None
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    transcript += chunk
                    if b"[y/N]" in transcript and not sent:
                        os.write(fd, (answer if answer == "\x03" else answer + "\n").encode())
                        sent = True
                    if b"MUSE_INPUT_READY" in transcript and not input_sent:
                        os.write(fd,b"bypass-input\n")
                        input_sent = True
                done, value = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = value
                    break
            if status is None:
                done, value = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = value
            if status is None:
                os.killpg(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise AssertionError("Terminal handoff hung: " + transcript.decode(errors="replace"))
            assert os.waitstatus_to_exitcode(status) == 0, transcript.decode(errors="replace")
            assert sent, transcript.decode(errors="replace")
            if answer == "y":
                launch = json.loads(launched.read_text())
                assert Path(launch["cwd"]).resolve() == app.resolve()
                assert len(launch["args"]) == 1 and "bypass_onboarding" in launch["args"][0]
                assert launch["input"] == "bypass-input\n"
                assert len(json.loads(approvals.read_text())) == 2
            else:
                assert not launched.exists() and not approvals.exists()
        finally:
            os.close(fd)
print("Terminal handoff passed: piped and direct startup, interactive terminal input, same-folder onboarding, decline and cancellation without approval.")
