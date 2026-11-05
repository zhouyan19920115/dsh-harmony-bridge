// The store scanner: the part of the bridge that walks the DSH session store and inflates the
// message logs.
//
// Why it lives in its own thread:
//   the work is CPU bound (every session log is zstd compressed JSON Lines and has to be
//   inflated), and on a machine with a few thousand messages one round takes seconds. On the
//   main thread that blocks the event loop, and then even `GET /_dsh/discover` — "is there a
//   desktop agent here?" — takes seconds. The phone gives up after a few hundred milliseconds
//   and reports "no desktop found", even though the bridge is right there.
//
// The split is deliberately simple:
//   - the worker only READS files and COMPUTES (it owns the index and nothing else),
//   - the main thread only USES the result.
// Nothing is shared between them: the worker posts plain snapshots, the main thread serves them.
//
// The order of the answers matters: the cheap metadata (the session list) is posted first, so
// the phone sees the sessions right away, and the expensive message counts trickle in behind it.
//
// If the worker thread cannot be started (a bundled build without a worker file, a platform
// without worker_threads), the same work is done on the main thread, but in small pieces, so
// the event loop is never blocked for more than a few milliseconds at a time.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker, isMainThread, parentPort } from 'node:worker_threads';

import { StoreIndex } from './store.js';

/* ------------------------------------------------------------------ the worker side */

if (!isMainThread && parentPort !== null) {
  const index = new StoreIndex();
  // The pause between two batches: the other threads of the machine get their turn.
  // The timer is **not** unref'd: a worker that waits on an unref'd timer can be torn down
  // while it waits, and that crashes the process on exit.
  const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
  // Only ONE scan runs at a time. A second request while a scan runs does not start a second
  // scan (that would eat the machine twice as fast and starve the bridge itself), it only
  // remembers that another round is due.
  let scanning = false;
  let again = false;
  // Set when the main thread asks the worker to stop. The scan leaves at the next batch
  // border, the port is closed and the thread ends on its own.
  let stopping = false;

  // The port can be closed while a scan still runs (the main thread may go away first), and
  // posting to a closed port throws. The message is simply dropped in that case.
  const post = (message) => {
    try {
      parentPort.postMessage(message);
    } catch {
      // The port is closed; nobody is listening any more.
    }
  };

  // Let the thread end by itself: the port does not keep the event loop alive any more.
  const closePort = () => {
    try {
      parentPort.close();
    } catch {
      // Already closed.
    }
  };

  const runScan = async (batchSize) => {
    // 1. The directory walk: cheap, and it is what the phone needs to see the sessions.
    index.refresh();
    post({ type: 'index', entries: index.all() });
    // 2. The message counts: the expensive part. It stays in this thread, so the event
    //    loop of the bridge keeps running while the logs are inflated.
    let more = true;
    while (more) {
      // The main thread wants to stop: leave the rest of the logs alone. The thread is not
      // killed, it simply stops working and leaves by itself.
      if (stopping) break;
      index.computePendingCounts(batchSize);
      post({ type: 'counts', entries: index.lastCounted });
      more = index.hasPending();
      // A short pause between two batches: the bridge answers its requests in between, even
      // when the machine is busy. It is also the moment the "stop" message is picked up.
      if (more) await sleep(10);
    }
  };

  parentPort.on('message', async (message) => {
    if (message?.type === 'stop') {
      // The graceful way out. The scan stops at the next batch border (a batch is a few
      // milliseconds), the thread ends on its own, and nothing has to be killed.
      stopping = true;
      post({ type: 'stopping' });
      if (!scanning) closePort();
      return;
    }
    if (message?.type !== 'scan') return;
    const batchSize = Number.isInteger(message.batchSize) ? message.batchSize : 4;
    if (scanning) {
      again = true;
      return;
    }
    scanning = true;
    try {
      do {
        again = false;
        await runScan(batchSize);
      } while (again && !stopping);
    } catch (error) {
      post({
        type: 'error',
        message: error instanceof Error ? error.message : String(error),
      });
    } finally {
      scanning = false;
      post({ type: 'done' });
      // The thread has nothing left to do: it may end now.
      if (stopping) closePort();
    }
  });
}

/* ------------------------------------------------------------------ the client side */

/**
 * The files that may hold the worker.
 *
 * 1. `worker\scan-worker.js` next to the executable — that is the single file build, where the
 *    sources live inside the snapshot and a thread cannot be started from there.
 * 2. next to this module — that is the repository and the source package.
 *
 * The order matters: inside the snapshot the file *exists* (as bytecode), but a thread cannot
 * be started from there, so the copy next to the executable has to win.
 */
function workerCandidates() {
  const candidates = [];
  const add = (file) => {
    // Only a file that really exists: a path that does not exist would swallow the scan
    // request (a worker that cannot load its module never answers).
    try {
      if (fs.existsSync(file)) candidates.push(file);
    } catch {
      // An unreadable path is not a candidate.
    }
  };
  try {
    add(path.join(path.dirname(process.execPath), 'worker', 'scan-worker.js'));
  } catch {
    // No executable path (an exotic runtime).
  }
  try {
    add(path.join(path.dirname(fileURLToPath(import.meta.url)), 'scan-worker.js'));
  } catch {
    // A bundled build has no real path for the module.
  }
  return candidates;
}

/**
 * Drives the store scanner.
 *
 * The API is intentionally tiny: {@link requestScan} asks for a scan, the index is filled in
 * when the result arrives. The caller never waits for the scan.
 */
export class ScanWorker {
  constructor({ index, log = () => {}, batchSize = 4 } = {}) {
    this.index = index;
    this.log = log;
    this.batchSize = batchSize;
    /** The worker thread, or `null` when the scan runs inline. */
    this.worker = null;
    /** 'worker' | 'inline' | 'off' */
    this.mode = 'off';
    /** A scan is in flight. */
    this.busy = false;
    /** A scan was asked for while one was running. */
    this.queued = false;
    /** The timer of the inline fallback. */
    this.inlineTimer = null;
    /** How many logs the inline fallback inflates per tick (small: it must not block). */
    this.inlineBatchSize = 2;
    /** The pause between two inline batches (the other requests get their turn). */
    this.inlineDelayMs = 5;
    /** How long a worker may take to leave after it was asked to stop. */
    this.stopTimeoutMs = 10_000;
    /** The scanner was stopped on purpose: a worker that leaves must not fall back to inline. */
    this.stopping = false;
    /** Resolved as soon as the first scan result arrived (the session list is ready). */
    this.firstScan = null;
    this.firstScanResolve = null;
  }

  /** Start the scanner. Returns `true` when it runs in its own thread. */
  start() {
    this.stopping = false;
    if (this.firstScan === null) {
      this.firstScan = new Promise((resolve) => { this.firstScanResolve = resolve; });
    }
    const candidates = workerCandidates();
    this.#tryCandidate(0, candidates);
    return this.mode === 'worker';
  }

  /**
   * Wait for the first scan result.
   *
   * The session list needs the store metadata; the phone asks for it right after connecting.
   * Waiting for the answer of the scanner thread does not block the event loop, so the
   * discovery probe is answered instantly even while the scan is running.
   */
  whenScanned(timeoutMs = 10_000) {
    if (this.firstScan === null) this.start();
    return Promise.race([
      this.firstScan,
      new Promise((resolve) => { setTimeout(resolve, timeoutMs).unref?.(); }),
    ]);
  }

  /** Ask for a scan. The call never blocks. */
  requestScan(reason = 'poll') {
    if (this.mode === 'inline') {
      this.#scheduleInlineScan();
      return;
    }
    if (this.mode !== 'worker' || this.worker === null) return;
    if (this.busy) {
      this.queued = true;
      return;
    }
    this.busy = true;
    try {
      this.worker.postMessage({ type: 'scan', reason, batchSize: this.batchSize });
    } catch (error) {
      this.busy = false;
      this.log('warn', `the store scan could not be started: ${error.message}`);
    }
  }

  /** Stop the scanner. */
  stop() {
    if (this.inlineTimer !== null) {
      clearTimeout(this.inlineTimer);
      this.inlineTimer = null;
    }
    const worker = this.worker;
    this.worker = null;
    this.mode = 'off';
    this.busy = false;
    this.queued = false;
    if (worker !== null) this.#stopWorker(worker);
    this.firstScanResolve?.();
    this.firstScanResolve = null;
  }

  /**
   * Stop a worker without killing it.
   *
   * `worker.terminate()` stops the thread right where it is, and when that happens inside the
   * zstd decompressor the whole process dies: "Assertion failed: init_done_ && 'close before
   * init'" (node_zlib.cc) followed by "FATAL ERROR: v8::HandleScope::CreateHandle() Cannot
   * create a handle without a HandleScope". The scan takes seconds on a real store, so this
   * happened in roughly one of three test runs.
   *
   * So the worker is asked to stop, leaves on its own at the next batch border, and
   * `terminate()` is only the fallback for a worker that does not answer in time.
   */
  #stopWorker(worker) {
    this.stopping = true;
    const fallback = setTimeout(() => {
      try {
        worker.terminate();
      } catch {
        // The worker is already gone.
      }
    }, this.stopTimeoutMs);
    // The fallback must not keep the process alive on its own.
    fallback.unref?.();
    worker.once('exit', () => { clearTimeout(fallback); });
    try {
      worker.postMessage({ type: 'stop' });
    } catch {
      // The worker is already gone: there is nothing left to stop.
      clearTimeout(fallback);
    }
  }

  /** Start the next candidate, or fall back to the inline scan. */
  #tryCandidate(index, candidates) {
    if (index >= candidates.length) {
      this.#useInline('the worker thread could not be started');
      return;
    }
    const file = candidates[index];
    let worker;
    try {
      worker = new Worker(file);
    } catch (error) {
      this.log('warn', `the store scanner (${file}) could not be started: ${error.message}`);
      this.#tryCandidate(index + 1, candidates);
      return;
    }
    this.stopping = false;
    let failed = false;
    worker.once('error', (error) => {
      failed = true;
      this.log('warn', `the store scanner (${file}) failed: ${error.message}`);
      // The thread is on its way out already; ask it to leave instead of killing it.
      this.#stopWorker(worker);
      if (this.worker === worker) this.worker = null;
      this.#tryCandidate(index + 1, candidates);
    });
    worker.on('message', (message) => {
      if (!failed) this.#onMessage(message);
    });
    worker.on('exit', (code) => {
      if (failed) return;
      if (this.worker === worker) this.worker = null;
      // The scanner was stopped on purpose: this is not a crash, do not fall back to inline.
      if (this.stopping) return;
      this.#useInline(`the store scanner stopped (code ${code})`);
    });
    this.worker = worker;
    this.mode = 'worker';
    this.log('info', `the store scanner runs in its own thread (${file})`);
  }

  /** The worker cannot run: do the same work here, in small pieces. */
  #useInline(reason) {
    if (this.mode === 'inline') return;
    this.mode = 'inline';
    this.log('warn', `${reason}, the store scan runs in small pieces on the main thread`);
    // The inline scan still fills the index, so the session list is not empty.
    this.#scheduleInlineScan();
  }

  /** A scan result arrived. */
  #onMessage(message) {
    if (message?.type === 'error') {
      this.busy = false;
      this.log('warn', `the store scan failed: ${message.message}`);
      this.firstScanResolve?.();
      this.firstScanResolve = null;
      return;
    }
    if (message?.type === 'index') {
      try {
        this.index.applyEntries(message.entries);
      } catch (error) {
        this.log('warn', `the store scan result could not be applied: ${error.message}`);
      }
      this.firstScanResolve?.();
      this.firstScanResolve = null;
      return;
    }
    if (message?.type === 'counts') {
      try {
        this.index.applyCountedEntries(message.entries);
      } catch (error) {
        this.log('warn', `the message counts could not be applied: ${error.message}`);
      }
      return;
    }
    if (message?.type === 'done') {
      this.busy = false;
      if (this.queued) {
        this.queued = false;
        this.requestScan('queued');
      }
    }
  }

  /** The inline fallback: one small batch per tick, so the event loop stays free. */
  #scheduleInlineScan() {
    if (this.inlineTimer !== null) return;
    this.inlineTimer = setTimeout(() => {
      this.inlineTimer = null;
      try {
        // The directory walk is one call; it is the cheapest part of the scan.
        this.index.refresh();
        this.index.applyEntries(this.index.all());
        this.firstScanResolve?.();
        this.firstScanResolve = null;
        // The counts: a few logs per tick, so the event loop is never blocked for long.
        this.index.computePendingCounts(this.inlineBatchSize);
        this.index.applyCountedEntries(this.index.lastCounted);
        if (this.index.hasPending()) this.#scheduleInlineScan();
      } catch (error) {
        this.log('warn', `the store scan failed: ${error.message}`);
      }
      // The next batch waits a little: the timer gives the other requests their turn.
    }, this.inlineDelayMs);
    this.inlineTimer.unref?.();
  }
}
