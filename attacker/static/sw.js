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
      netTimes.push(performance.now() - t0);
      lastResponse = res;
    }

    // 2. Service Worker Cache API timing (post-download, 15 store/delete cycles)
    const cache = await caches.open('timing-demo');
    const swTimes = [];
    for (let i = 0; i < 15; i++) {
      const cloned = lastResponse.clone();
      const t0 = performance.now();
      await cache.put('/probe-' + i, cloned);
      await cache.delete('/probe-' + i);
      swTimes.push(performance.now() - t0);
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
