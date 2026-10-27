"""Exercise curl-style piped stdin with a real terminal and a fixture Muse host."""
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import sys
import tempfile
import time

root = Path(__file__).resolve().parent.parent
node = sys.argv[1]
for answer in ("y", "n"):
    with tempfile.TemporaryDirectory(prefix="bypass-terminal-") as temporary:
        base = Path(temporary)
        app = base / "customer app & Ω"
        app.mkdir()
        fake = base / "bin"
        fake.mkdir()
        launched = base / "launch.json"
        approvals = base / "approvals.json"
        host = fake / "muse"
        host.write_text("#!" + sys.executable + "\nimport json,os,sys\nfrom pathlib import Path\n"
                        + "Path(" + repr(str(launched)) + ").write_text(json.dumps({'cwd':os.getcwd(),'args':sys.argv[1:]}))\n")
        host.chmod(0o755)
        driver = base / "setup.mjs"
        driver.write_text("""
import fs from 'node:fs';
import {setupTerminal,finishMuseSetup} from MODULE;
const value={valid:true,active:true,record:{package_sha256:'fixture',cache_path:'fixture'},runtime_capabilities:['hook:session-context','mcp_server:security'].map(id=>({candidate:{stable_id:'plugin:bypass:'+id},status:'review_needed'}))};
const terminal=setupTerminal();
if(!terminal)throw new Error('Piped installer did not find its controlling terminal');
try{
 await finishMuseSetup({cwd:process.cwd(),inspect:async()=>structuredClone(value),approve:async id=>{value.runtime_capabilities.find(row=>row.candidate.stable_id===id).status='trusted_enabled';fs.writeFileSync(APPROVALS,JSON.stringify(value.runtime_capabilities));},ask:terminal.ask,launch:terminal.launch});
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
            os.execve("/bin/bash", ["bash", "-c", "cat " + shlex.quote(str(bootstrap)) + " | bash"], env)
        transcript = b""
        sent = False
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
                        os.write(fd, (answer + "\n").encode())
                        sent = True
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
                assert len(json.loads(approvals.read_text())) == 2
            else:
                assert not launched.exists() and not approvals.exists()
        finally:
            os.close(fd)
print("Terminal handoff passed: piped installer, explicit consent, same-folder startup, decline without approval.")
