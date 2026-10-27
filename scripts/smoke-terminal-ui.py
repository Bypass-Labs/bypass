"""Exercise the real CLI in a PTY; save complete frames for visual review."""
import fcntl,json,os,pty,re,select,signal,struct,sys,tempfile,termios,time
from pathlib import Path
root=Path(__file__).resolve().parent.parent
node=sys.argv[1]
artifacts=Path(sys.argv[2]) if len(sys.argv)>2 else Path(tempfile.mkdtemp(prefix='bypass-ui-frames-'))
artifacts.mkdir(parents=True,exist_ok=True)
marker=b'\x1b[?25l\x1b[H'
complete_frame=re.compile(re.escape(marker)+rb'.*?\x1b\[\d+;\d+H(?:\x1b\[\?25h)?',re.S)
def run(args,cwd,check,timeout=60):
    pid,fd=pty.fork()
    if pid==0:
        os.chdir(cwd)
        env=dict(os.environ,TERM='xterm-256color',COLORTERM='truecolor')
        for key in ['NO_COLOR','CI','BYPASS_PLAIN']:env.pop(key,None)
        os.execve(node,[node,str(root/'bin/bypass.mjs'),*args],env)
    fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',38,130,0,0))
    transcript=b'';buffer=b'';status=None;start=time.monotonic()
    try:
        while time.monotonic()-start<timeout:
            if select.select([fd],[],[],.1)[0]:
                try:chunk=os.read(fd,131072)
                except OSError:break
                if not chunk:break
                transcript+=chunk
                buffer+=chunk
                frames=list(complete_frame.finditer(buffer))
                if frames:
                    frame=frames[-1].group()
                    buffer=buffer[frames[-1].end():]
                    check(frame,fd,pid)
            done,value=os.waitpid(pid,os.WNOHANG)
            if done:status=value;break
        if status is None:
            done,value=os.waitpid(pid,os.WNOHANG)
            if done:status=value
        if status is None:
            os.killpg(pid,signal.SIGTERM)
            time.sleep(.5)
            done,value=os.waitpid(pid,os.WNOHANG)
            if not done:os.killpg(pid,signal.SIGKILL);os.waitpid(pid,0)
            raise AssertionError('CLI did not finish; last frame: '+transcript[-12000:].decode(errors='replace'))
        return os.waitstatus_to_exitcode(status)
    finally:os.close(fd)
with tempfile.TemporaryDirectory(prefix='bypass-ui-app-',dir='/tmp') as temporary:
    app=Path(temporary)
    captured=[]
    def welcome(frame,fd,pid):
        if b'How would you like to start?' in frame and not captured:
            assert b'BYPASS LABS' in frame and b'NOW' in frame and b'NEXT' in frame
            assert b'38;2;255;74;44' in frame
            (artifacts/'welcome.ansi').write_bytes(frame);captured.append('welcome');os.write(fd,b'\x03')
    assert run([],app,welcome)==130
    step=[1]
    def demo(frame,fd,pid):
        expected=(str(step[0])+' / 6').encode()
        if step[0]<=6 and expected in frame:
            if step[0]==4:
                assert b'3/6 done' in frame
                (artifacts/'walkthrough.ansi').write_bytes(frame)
            os.write(fd,b'\r');step[0]+=1
        elif step[0]==7 and b'Enter to finish' in frame:
            assert b'6/6 done' in frame
            (artifacts/'complete.ansi').write_bytes(frame);os.write(fd,b'\r');step[0]+=1
    assert run(['demo','--dir',str(app/'ledger')],app,demo)==0
    assert step[0]==8
    state=json.loads((app/'ledger/.bypass/state.json').read_text())
    assert len(state['checks'])==1 and state['checks'][0]['lastResult']['status']=='passed'
    assert not any(m['enabled'] for m in state['monitors'])
    stage=[0]
    def commands(frame,fd,pid):
        if stage[0]==0 and b'/ commands' in frame:
            os.write(fd,b'/');stage[0]=1
        elif stage[0]==1 and b'/review' in frame and b'/demo' in frame:
            (artifacts/'commands.ansi').write_bytes(frame)
            fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',15,40,0,0));os.kill(pid,signal.SIGWINCH);stage[0]=2
        elif stage[0]==2 and frame.count(b'\x1b[2K')==15 and b'Ctrl+C exit' in frame:
            (artifacts/'narrow.ansi').write_bytes(frame)
            os.write(fd,b'\x1b');stage[0]=3
        elif stage[0]==3 and b'Enter:' in frame:
            os.write(fd,b'/quit\r');stage[0]=4
    assert run(['--project',str(app/'ledger')],app,commands)==0
    assert stage[0]==4
print(json.dumps({'terminalUi':'passed','welcome':True,'sixStepHttpWalkthrough':True,'exportedRegression':True,'commandMenu':True,'resize':'40x15','modelCalls':0,'artifacts':str(artifacts)}))
