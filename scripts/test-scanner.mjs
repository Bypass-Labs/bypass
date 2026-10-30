import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const result = spawnSync(process.env.PYTHON || 'python3', ['-m', 'unittest', 'discover', '-s', 'scanner/tests'], {
  cwd: root,
  env: {...process.env, PYTHONPATH: fileURLToPath(new URL('../scanner/src', import.meta.url)), PYTHONDONTWRITEBYTECODE: '1'},
  stdio: 'inherit',
});
if (result.error) console.error(result.error.message);
process.exitCode = result.status ?? 1;
