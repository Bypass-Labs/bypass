"""Exercise the shipped setup entrypoint in a PTY with an isolated Muse fixture."""
import fcntl,json,os,pty,re,select,signal,struct,sys,tempfile,termios,time
from pathlib import Path

root=Path(__file__).resolve().parent.parent
node=sys.argv[1]
artifacts=Path(sys.argv[2]) if len(sys.argv)>2 else Path(tempfile.mkdtemp(prefix='bypass-install-frames-'))
artifacts.mkdir(parents=True,exist_ok=True)
ansi=re.compile(rb'\x1b\[[0-9;?]*[A-Za-z]')
for mode in ['success','narrow','resize','failure','cancel','cancel-remove']:
    with tempfile.TemporaryDirectory(prefix='bypass-setup-pty-') as temporary:
        base=Path(temporary);app=base/'app';app.mkdir();bin_dir=base/'bin';bin_dir.mkdir()
        state=base/'installed.json';installing=base/'installing';calls=base/'calls.jsonl'
        fixture={'valid':True,'active':True,'record':{'id':'bypass','package_sha256':'fixture','cache_path':str(base/'cache'),'source':{'path':str(base/'previous-plugin')}},'runtime_capabilities':[{'candidate':{'stable_id':'plugin:bypass:'+cap},'status':'review_needed'} for cap in ['hook:session-context','mcp_server:security']]}
        if mode.startswith('cancel'):state.write_text(json.dumps(fixture))
        host=bin_dir/'muse'
        host.write_text('#!'+sys.executable+'\n'+"""
import json,os,sys,time
from pathlib import Path
base=Path(BASE);state=base/'installed.json';args=sys.argv[1:]
with (base/'calls.jsonl').open('a') as f:f.write(json.dumps(args)+'\\n')
if args[1]=='inspect':
    print(state.read_text() if state.exists() else '{"error":{"message":"not installed"}}');sys.exit(0 if state.exists() else 1)
if args[1]=='validate':print('{"valid":true}');sys.exit(0)
if args[1]=='remove':
    state.unlink()
    if MODE=='cancel-remove':
        (base/'installing').write_text(str(os.getpid()));time.sleep(90)
    print('{"removed":true}');sys.exit(0)
assert args[1]=='install',args
if args[2]==str(base/'previous-plugin'):
    state.write_text(FIXTURE);print('{"restored":true}');sys.exit(0)
(base/'installing').write_text(str(os.getpid()))
time.sleep(90 if MODE=='cancel' else 2)
if MODE=='failure':print('{"error":{"message":"Fixture installation failed"}}');sys.exit(1)
state.write_text(FIXTURE);print('{"installed":true}')
""".replace('BASE',repr(str(base))).replace('FIXTURE',repr(json.dumps(fixture))).replace('MODE',repr(mode)))
        host.chmod(0o755)
        pid,fd=pty.fork()
        if pid==0:
            os.chdir(app)
            env=dict(os.environ,PATH=str(bin_dir)+os.pathsep+os.environ['PATH'],TERM='xterm-256color',COLORTERM='truecolor',BYPASS_NO_OPEN_MUSE='1')
            for key in ['CI','NO_COLOR','BYPASS_PLAIN']:env.pop(key,None)
            os.execve(node,[node,str(root/'bin/muse-setup.mjs')],env)
        columns=40 if mode=='narrow' else 100
        fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',32,columns,0,0))
        transcript=b'';status=None;sent=False;snapshot=None;frames=[];start=time.monotonic()
        try:
            while time.monotonic()-start<20:
                if select.select([fd],[],[],.05)[0]:
                    try:chunk=os.read(fd,65536)
                    except OSError:break
                    if not chunk:break
                    transcript+=chunk
                    if installing.exists() and b'\x1b[J' in transcript:
                        current=transcript.rsplit(b'\x1b[J',1)[-1]
                        plain=ansi.sub(b'',current).decode(errors='replace')
                        if '○ Verify installation' in plain and 'Installing tools' in plain:
                            frames.append(current)
                            if '1s' in plain:snapshot=current
                    if installing.exists() and not sent:
                        if mode.startswith('cancel'):os.kill(pid,signal.SIGINT);sent=True
                        elif mode=='resize':
                            fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',32,40,0,0));os.kill(pid,signal.SIGWINCH);sent=True
                done,value=os.waitpid(pid,os.WNOHANG)
                if done:status=value;break
            if status is None:
                deadline=time.monotonic()+2
                while time.monotonic()<deadline:
                    done,value=os.waitpid(pid,os.WNOHANG)
                    if done:status=value;break
                    time.sleep(.01)
            if status is None:
                os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
                raise AssertionError('Setup hung: '+transcript[-4000:].decode(errors='replace'))
            plain=ansi.sub(b'',transcript).decode(errors='replace')
            expected=130 if mode.startswith('cancel') else 3 if mode=='failure' else 0
            assert os.waitstatus_to_exitcode(status)==expected,plain[-4000:]
            assert 'Check setup' in plain and '○ Verify installation' in plain
            assert 'Still installing the plugin' not in plain
            assert '\x1b[?25l' not in transcript.decode(errors='replace'),'Installer must not leave the cursor hidden'
            operations=[json.loads(line)[1] for line in calls.read_text().splitlines()]
            if mode in ['success','narrow','resize']:
                assert 'Plugin installed and verified' in plain and 'Runtime' in plain
                assert operations==['inspect','validate','install','inspect','inspect'],operations
                assert len(frames)>=4 and len(set(frames))>=3,'Spinner did not redraw during the slow host operation'
                assert snapshot is not None
                (artifacts/(mode+'.ansi')).write_bytes(snapshot)
                if mode in ['narrow','resize']:
                    assert all(len(line)<40 for line in ansi.sub(b'',snapshot).decode().splitlines()),snapshot
            else:
                assert 'Plugin installed and verified' not in plain
                if mode.startswith('cancel'):
                    assert 'Restore previous plugin' in plain and 'Setup cancelled' in plain
                    assert json.loads(state.read_text())==fixture
                    assert operations[-1]=='install',operations
                else:assert 'Fixture installation failed' in plain
            (artifacts/(mode+'-transcript.ansi')).write_bytes(transcript)
        finally:os.close(fd)
print(json.dumps({'installerProgress':'passed','scenarios':['live spinner','real stages','narrow','resize','failure','cancel and restore'],'userInstallationTouched':False,'artifacts':str(artifacts)}))
