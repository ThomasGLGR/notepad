"use strict";
globalThis.SOCCaptureQueue = (() => {
  const KEY = "soc-capture.queue.v1";
  const LEASE_MS = 30000;
  function create({ storage, isFocused, now = Date.now, makeId = () => crypto.randomUUID() }) {
    let tail = Promise.resolve();
    const serial = task => {
      const operation = tail.then(task);
      tail = operation.catch(() => {});
      return operation;
    };
    async function read() {
      const saved = (await storage.get(KEY))[KEY];
      const queue = saved || { version: 1, captures: [], claim: null };
      if (queue.claim && queue.claim.expiresAt <= now()) releaseClaim(queue);
      return queue;
    }
    const write = queue => storage.set({ [KEY]: queue });
    function releaseClaim(queue) {
      for (const capture of queue.captures) capture.state = "pending";
      queue.claim = null;
    }
    const owns = (claim, owner, token) => claim && claim.token === token && claim.owner.clientId === owner.clientId && claim.owner.tabId === owner.tabId;
    function enqueue(capture) {
      return serial(async () => {
        const item = globalThis.SOCCaptureData.validate(capture);
        if (!item) throw Error("Invalid capture");
        const queue = await read();
        if (item.method === "json") {
          if (!item.digest) throw Error("Missing JSON digest");
          const receipt = queue.jsonReceipts?.find(receipt => receipt.id === item.id);
          if (receipt) {
            if (receipt.digest !== item.digest || receipt.origin !== new URL(item.url).origin) throw Error("JSON send ID reused with different data");
            return queue.captures.length;
          }
          if ((queue.jsonReceipts?.length || 0) >= 5000) throw Error("JSON send receipt limit reached");
        }
        if (queue.captures.some(record => record.id === item.id)) return queue.captures.length;
        if (queue.captures.length >= 1000 || queue.captures.reduce((size, record) => size + record.value.length, item.value.length) > 3000000) throw Error("Capture queue full");
        queue.captures.push({ ...item, state: "pending" });
        if (item.method === "json") {
          queue.jsonReceipts ||= [];
          queue.jsonReceipts.push({ id: item.id, digest: item.digest, origin: new URL(item.url).origin, status: "queued" });
        }
        queue.captures.sort((a, b) => a.timestamp - b.timestamp);
        await write(queue);
        return queue.captures.length;
      });
    }
    function claim(owner, { jsonOnly = false } = {}) {
      return serial(async () => {
        if (!jsonOnly && !await isFocused(owner.tabId)) return null;
        const queue = await read();
        if (queue.claim) {
          if (jsonOnly && queue.captures.some(item => item.state === "claimed" && item.method !== "json")) return null;
          if (jsonOnly && queue.claim.owner.tabId !== owner.tabId) return null;
          if (queue.claim.owner.clientId === owner.clientId && queue.claim.owner.tabId === owner.tabId) return { ...queue.claim, captures: queue.captures.filter(item => item.state === "claimed") };
          // A reload replaces the client in the same tab. Otherwise the previous
          // owner must lose focus before a different Note Builder can take over.
          if (queue.claim.owner.tabId !== owner.tabId && await isFocused(queue.claim.owner.tabId)) return null;
          releaseClaim(queue);
        }
        const captures = queue.captures.filter(item => item.state === "pending" && (!jsonOnly || item.method === "json")).slice(0, 20);
        if (!captures.length) return null;
        const ids = captures.map(item => item.id);
        for (const item of captures) item.state = "claimed";
        queue.claim = { token: makeId(), owner, ids, expiresAt: now() + LEASE_MS };
        await write(queue);
        return { ...queue.claim, captures };
      });
    }
    function acknowledge(owner, token, ids) {
      return serial(async () => {
        const queue = await read();
        if (!owns(queue.claim, owner, token) || !Array.isArray(ids) || ids.length !== queue.claim.ids.length || new Set(ids).size !== ids.length || !queue.claim.ids.every(id => ids.includes(id))) return false;
        const completed = new Set(ids);
        for (const receipt of queue.jsonReceipts || []) if (completed.has(receipt.id)) { receipt.status = "imported"; delete receipt.error; }
        // This is the imported transition. Only acknowledged records are removed.
        queue.captures = queue.captures.filter(item => !completed.has(item.id));
        queue.claim = null;
        await write(queue);
        return true;
      });
    }
    function release(owner, token) {
      return serial(async () => {
        const queue = await read();
        if (!owns(queue.claim, owner, token)) return false;
        releaseClaim(queue);
        await write(queue);
        return true;
      });
    }
    function reportJSONError(owner, token, error) {
      return serial(async () => {
        const queue = await read();
        if (!owns(queue.claim, owner, token) || typeof error !== "string") return false;
        for (const receipt of queue.jsonReceipts || []) if (queue.claim.ids.includes(receipt.id)) receipt.error = error.slice(0, 240);
        await write(queue);
        return true;
      });
    }
    const snapshot = () => serial(read);
    return Object.freeze({ enqueue, claim, acknowledge, release, reportJSONError, snapshot });
  }
  return Object.freeze({ create, KEY, LEASE_MS });
})();
if (typeof module !== "undefined") module.exports = globalThis.SOCCaptureQueue;
