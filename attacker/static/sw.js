self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('message', async (event) => {
  const port = event.ports[0];
  const target = event.data && event.data.target;

  if (!target) {
    port.postMessage({ ok: false, error: 'Missing target URL in probe message.' });
    return;
  }

  try {
    const cache = await caches.open('timing-demo');

    // 1. Classic network timing (5 cross-site no-cors downloads)
    const netTimes = [];
    let lastResponse = null;
    for (let i = 0; i < 5; i++) {
      const t0 = performance.now();
      const res = await fetch(target + '?cb=' + Math.random(), {
        mode: 'no-cors',
        credentials: 'include',
        cache: 'no-store',
      });
      if (i === 4) {
        lastResponse = res.clone();
      }
      // Drain the opaque body completely so the browser doesn't abort the socket mid-transfer
      await cache.put('/net-drain', res);
      netTimes.push(performance.now() - t0);
    }
    await cache.delete('/net-drain');

    // 2. Service Worker Cache API timing (post-download, batched puts to amplify size signal)
    const BATCHES = 5;
    const PUTS_PER_BATCH = 10;
    const swTimes = [];

    for (let b = 0; b < BATCHES; b++) {
      const clones = [];
      for (let i = 0; i < PUTS_PER_BATCH; i++) {
        clones.push(lastResponse.clone());
      }

      const t0 = performance.now();
      for (let i = 0; i < PUTS_PER_BATCH; i++) {
        await cache.put('/probe-' + i, clones[i]);
      }
      swTimes.push(performance.now() - t0);

      for (let i = 0; i < PUTS_PER_BATCH; i++) {
        await cache.delete('/probe-' + i);
      }
    }

    const median = (arr) => {
      const sorted = [...arr].sort((a, b) => a - b);
      return sorted[Math.floor(sorted.length / 2)];
    };

    port.postMessage({
      ok: true,
      netMedian: median(netTimes).toFixed(2),
      netSpread: (Math.max(...netTimes) - Math.min(...netTimes)).toFixed(2),
      swMedian: median(swTimes).toFixed(2),
      swSpread: (Math.max(...swTimes) - Math.min(...swTimes)).toFixed(2),
    });
  } catch (err) {
    port.postMessage({ ok: false, error: String(err) });
  }
});
