// Run from any directory with: node start.js
const { spawn } = require('node:child_process');
const path = require('node:path');

const services = [];
let stopping = false;

function stop(exitCode) {
  if (stopping) return;
  stopping = true;
  for (const service of services) service.kill();
  process.exitCode = exitCode;
}

function start(folder, argumentsList, environment = {}) {
  const service = spawn(process.execPath, argumentsList, {
    cwd: path.join(__dirname, folder),
    env: { ...process.env, ...environment },
    stdio: 'inherit'
  });
  services.push(service);
  service.on('error', error => {
    console.error(error.message);
    stop(1);
  });
  service.on('exit', code => stop(code ?? 1));
}

const port = process.env.PORT || '5000';
start('server', ['app.js']);
start('client', ['node_modules/vite/bin/vite.js', '--port', '5173', '--strictPort'], {
  VITE_API_BASE: process.env.VITE_API_BASE || `http://localhost:${port}/api`
});
process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));
