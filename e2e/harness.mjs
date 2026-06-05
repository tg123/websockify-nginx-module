// Shared end-to-end test harness.
//
// Boots a raw TCP "echo" backend (a stand-in for a real websockify upstream
// such as a VNC server) and an nginx instance built with the websockify
// module, then exposes the public WebSocket endpoint for the tests.
import net from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

// Resolve the nginx binary. CI/local callers can override with NGINX_BIN.
export const NGINX_BIN = process.env.NGINX_BIN || 'nginx';

// Find a free TCP port by binding to port 0 and reading the assigned port.
export function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function waitForPort(port, host = '127.0.0.1', timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryConnect = () => {
      const sock = net.connect(port, host);
      sock.once('connect', () => {
        sock.destroy();
        resolve();
      });
      sock.once('error', () => {
        sock.destroy();
        if (Date.now() > deadline) {
          reject(new Error(`timed out waiting for ${host}:${port}`));
        } else {
          setTimeout(tryConnect, 50);
        }
      });
    };
    tryConnect();
  });
}

// A TCP echo server that simply mirrors back every byte it receives.
export function startEchoBackend(port) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.on('data', (chunk) => socket.write(chunk));
      socket.on('error', () => {});
    });
    server.on('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

// Launch an nginx instance with a single `location /websockify` that proxies
// to the given backend port. Returns a handle with `port` and `stop()`.
export async function startNginx({ backendPort, listenPort, extraLocationConfig = '' }) {
  const prefix = mkdtempSync(path.join(tmpdir(), 'websockify-e2e-'));
  mkdirSync(path.join(prefix, 'logs'), { recursive: true });
  mkdirSync(path.join(prefix, 'temp'), { recursive: true });

  const conf = `
daemon off;
worker_processes 1;
pid ${prefix}/nginx.pid;
error_log ${prefix}/logs/error.log debug;

events {
    worker_connections 1024;
}

http {
    access_log off;
    client_body_temp_path ${prefix}/temp/client_body;
    proxy_temp_path ${prefix}/temp/proxy;
    fastcgi_temp_path ${prefix}/temp/fastcgi;
    uwsgi_temp_path ${prefix}/temp/uwsgi;
    scgi_temp_path ${prefix}/temp/scgi;

    server {
        listen 127.0.0.1:${listenPort};

        location /websockify {
            websockify_pass 127.0.0.1:${backendPort};
            ${extraLocationConfig}
        }
    }
}
`;
  const confPath = path.join(prefix, 'nginx.conf');
  writeFileSync(confPath, conf);

  // Validate config up-front for a clearer failure message.
  const check = spawnSync(NGINX_BIN, ['-t', '-p', prefix, '-c', confPath], {
    encoding: 'utf8',
  });
  if (check.status !== 0) {
    rmSync(prefix, { recursive: true, force: true });
    throw new Error(`nginx config test failed:\n${check.stderr || check.stdout}`);
  }

  const proc = spawn(NGINX_BIN, ['-p', prefix, '-c', confPath], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  proc.stderr.on('data', (d) => {
    stderr += d.toString();
  });

  const stop = () =>
    new Promise((resolve) => {
      proc.once('exit', () => {
        rmSync(prefix, { recursive: true, force: true });
        resolve();
      });
      proc.kill('SIGTERM');
    });

  try {
    await waitForPort(listenPort);
  } catch (err) {
    await stop();
    throw new Error(`${err.message}\nnginx stderr:\n${stderr}`);
  }

  return { port: listenPort, prefix, stop };
}

// Bring up nginx pointing at a port with no listener, to simulate an
// unreachable upstream (for example a VNC host that is down).
export async function startStackWithDeadBackend(opts = {}) {
  const backendPort = await freePort(); // nothing ever listens here
  const listenPort = await freePort();
  const nginx = await startNginx({ backendPort, listenPort, ...opts });
  return {
    url: `ws://127.0.0.1:${listenPort}/websockify`,
    backendPort,
    listenPort,
    async stop() {
      await nginx.stop();
    },
  };
}

// Convenience: bring up backend + nginx together and return both handles.
export async function startStack(opts = {}) {
  const backendPort = await freePort();
  const listenPort = await freePort();
  const backend = await startEchoBackend(backendPort);
  let nginx;
  try {
    nginx = await startNginx({ backendPort, listenPort, ...opts });
  } catch (err) {
    backend.close();
    throw err;
  }
  return {
    url: `ws://127.0.0.1:${listenPort}/websockify`,
    backendPort,
    listenPort,
    async stop() {
      await nginx.stop();
      await new Promise((resolve) => backend.close(resolve));
    },
  };
}
