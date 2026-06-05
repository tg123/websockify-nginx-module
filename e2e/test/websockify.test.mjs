import test from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket } from 'ws';
import { startStack, startStackWithDeadBackend } from '../harness.mjs';

// Open a WebSocket against the running stack and resolve once connected.
function connect(url, protocol) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, protocol);
    ws.once('open', () => resolve(ws));
    ws.once('error', reject);
  });
}

// Collect raw bytes from the socket until `expected` bytes have arrived.
// For the base64 subprotocol the frames are base64 text, so decode them first.
function collectBytes(ws, expected, { base64 = false } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    const onMessage = (data, isBinary) => {
      const buf = base64
        ? Buffer.from(isBinary ? data.toString() : data.toString(), 'base64')
        : Buffer.isBuffer(data)
          ? data
          : Buffer.from(data);
      chunks.push(buf);
      total += buf.length;
      if (total >= expected) {
        ws.off('message', onMessage);
        resolve(Buffer.concat(chunks).subarray(0, expected));
      }
    };
    ws.on('message', onMessage);
    ws.once('error', reject);
    ws.once('close', () => {
      if (total < expected) {
        reject(new Error(`socket closed after ${total}/${expected} bytes`));
      }
    });
  });
}

test('binary subprotocol echoes binary payloads', async () => {
  const stack = await startStack();
  try {
    const ws = await connect(stack.url, 'binary');
    assert.equal(ws.protocol, 'binary');

    const payload = Buffer.from('hello websockify');
    const received = collectBytes(ws, payload.length);
    ws.send(payload);
    assert.deepEqual(await received, payload);

    ws.close();
  } finally {
    await stack.stop();
  }
});

test('base64 subprotocol decodes and re-encodes payloads', async () => {
  const stack = await startStack();
  try {
    const ws = await connect(stack.url, 'base64');
    assert.equal(ws.protocol, 'base64');

    const payload = Buffer.from('hello base64 world');
    const received = collectBytes(ws, payload.length, { base64: true });
    // Under the base64 protocol the client sends base64-encoded text frames.
    ws.send(payload.toString('base64'));
    assert.deepEqual(await received, payload);

    ws.close();
  } finally {
    await stack.stop();
  }
});

test('binary is preferred when both subprotocols are offered', async () => {
  const stack = await startStack();
  try {
    const ws = await connect(stack.url, ['base64', 'binary']);
    assert.equal(ws.protocol, 'binary');
    ws.close();
  } finally {
    await stack.stop();
  }
});

test('large payloads survive a round trip', async () => {
  const stack = await startStack();
  try {
    const ws = await connect(stack.url, 'binary');
    // Stream 1 MiB through the proxy in chunks below the module's single-frame
    // limit (MAX_WEBSOCKET_FRAME_SIZE = 65535) to exercise sustained buffering.
    const chunkSize = 16 * 1024;
    const chunks = 64;
    const total = chunkSize * chunks;
    const received = collectBytes(ws, total);
    for (let i = 0; i < chunks; i += 1) {
      ws.send(Buffer.alloc(chunkSize, i & 0xff));
    }
    const buf = await received;
    assert.equal(buf.length, total);
    // Spot-check the byte pattern at each chunk boundary.
    for (let i = 0; i < chunks; i += 1) {
      assert.equal(buf[i * chunkSize], i & 0xff);
    }
    ws.close();
  } finally {
    await stack.stop();
  }
});

test('connection without a supported subprotocol is rejected', async () => {
  const stack = await startStack();
  try {
    await assert.rejects(connect(stack.url, 'unsupported'));
  } finally {
    await stack.stop();
  }
});

test('a dead upstream closes the websocket connection', async () => {
  const stack = await startStackWithDeadBackend();
  try {
    const ws = await connect(stack.url, 'binary');
    // The handshake may complete, but with no upstream the connection must be
    // torn down rather than echoing any data back.
    const closed = new Promise((resolve) => ws.once('close', (code) => resolve(code)));
    ws.send(Buffer.from('ping'));
    const code = await Promise.race([
      closed,
      collectBytes(ws, 4).then(() => 'echoed'),
    ]);
    assert.notEqual(code, 'echoed', 'dead upstream must not echo data');
  } finally {
    await stack.stop();
  }
});
