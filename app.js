/* ══ ShadowVault — Frontend JS ═════════════════════════════════════════════ */

// ── Hex canvas background ──────────────────────────────────────────────────
(function initHexCanvas() {
  const canvas = document.getElementById('hexCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    drawHexGrid();
  }

  function hexPath(cx, cy, r) {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 3) * i - Math.PI / 6;
      const x = cx + r * Math.cos(a);
      const y = cy + r * Math.sin(a);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.closePath();
  }

  function drawHexGrid() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const r  = 38;
    const w  = r * 2;
    const h  = Math.sqrt(3) * r;
    const cols = Math.ceil(canvas.width  / (w * .75)) + 2;
    const rows = Math.ceil(canvas.height / h) + 2;

    for (let col = -1; col < cols; col++) {
      for (let row = -1; row < rows; row++) {
        const cx = col * w * 0.75;
        const cy = row * h + (col % 2 === 0 ? 0 : h / 2);
        hexPath(cx, cy, r - 1);
        ctx.strokeStyle = 'rgba(212,168,67,0.045)';
        ctx.lineWidth   = 1;
        ctx.stroke();
      }
    }
  }

  window.addEventListener('resize', resize);
  resize();
})();

// ── DOM refs ──────────────────────────────────────────────────────────────
const dropZone      = document.getElementById('dropZone');
const fileInput     = document.getElementById('fileInput');
const fileList      = document.getElementById('fileList');
const processBtn    = document.getElementById('processBtn');
const resultsSection = document.getElementById('resultsSection');
const resultsGrid   = document.getElementById('resultsGrid');
const reportRow     = document.getElementById('reportRow');
const reportLink    = document.getElementById('reportLink');
const loadingOverlay = document.getElementById('loadingOverlay');
const loadingSub    = document.getElementById('loadingSub');

// Vault demo
const demoSession   = document.getElementById('demoSession');
const demoToken     = document.getElementById('demoToken');
const roleChips     = document.getElementById('roleChips');
const decryptBtn    = document.getElementById('decryptBtn');
const termBody      = document.getElementById('termBody');

let selectedFiles  = [];
let activeRole     = null;
let currentSession = null;

// ── Drag & drop ───────────────────────────────────────────────────────────
['dragenter', 'dragover'].forEach(ev =>
  dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.add('drag-over'); })
);
['dragleave', 'drop'].forEach(ev =>
  dropZone.addEventListener(ev, e => { e.preventDefault(); dropZone.classList.remove('drag-over'); })
);
dropZone.addEventListener('drop',  e => addFiles(e.dataTransfer.files));
dropZone.addEventListener('click', e => { if (e.target !== fileInput) fileInput.click(); });
fileInput.addEventListener('change', () => addFiles(fileInput.files));

// ── File management ───────────────────────────────────────────────────────
function addFiles(fl) {
  const ok = ['pdf', 'jpg', 'jpeg', 'png'];
  Array.from(fl).forEach(f => {
    const ext = f.name.split('.').pop().toLowerCase();
    if (!ok.includes(ext)) return;
    if (selectedFiles.find(x => x.name === f.name && x.size === f.size)) return;
    selectedFiles.push(f);
  });
  renderFileList();
  fileInput.value = '';
}

function removeFile(i) { selectedFiles.splice(i, 1); renderFileList(); }

function renderFileList() {
  fileList.innerHTML = '';
  selectedFiles.forEach((f, i) => {
    const ext  = f.name.split('.').pop().toLowerCase();
    const icon = ext === 'pdf' ? '📄' : '🖼';
    const li   = document.createElement('li');
    li.className = 'file-item';
    li.innerHTML = `
      <span class="fi-icon">${icon}</span>
      <span class="fi-name">${esc(f.name)}</span>
      <span class="fi-size">${fmtSize(f.size)}</span>
      <button class="fi-remove" title="Remove" onclick="removeFile(${i})">✕</button>`;
    fileList.appendChild(li);
  });
  processBtn.disabled = selectedFiles.length === 0;
}

// ── Process (tokenise) ────────────────────────────────────────────────────
processBtn.addEventListener('click', async () => {
  if (!selectedFiles.length) return;

  const fd = new FormData();
  selectedFiles.forEach(f => fd.append('files', f));

  showLoading(true);
  animateLoading();

  let data;
  try {
    const res = await fetch('/api/tokenise', { method: 'POST', body: fd });
    data = await res.json();
  } catch (err) {
    showLoading(false);
    alert('Network error: ' + err.message);
    return;
  }

  showLoading(false);
  currentSession = data.session_id;

  // Auto-fill demo session
  if (demoSession) demoSession.value = currentSession;

  renderResults(data);
});

// ── Render results ────────────────────────────────────────────────────────
function renderResults(data) {
  resultsGrid.innerHTML = '';
  reportRow.style.display = 'none';

  data.results.forEach(r => {
    const card = document.createElement('div');
    const ok   = r.status === 'ok';
    const skip = r.status === 'skipped';
    card.className = `result-card ${ok ? 'has-ok' : r.status === 'error' ? 'has-error' : ''}`;

    const ext  = r.original.split('.').pop().toLowerCase();
    const icon = ext === 'pdf' ? '📄' : '🖼';

    let body = `
      <div class="rc-header">
        <span class="rc-icon">${icon}</span>
        <span class="rc-name">${esc(r.original)}</span>
        <span class="rc-status ${ok ? 'ok' : skip ? 'skip' : 'err'}">
          ${ok ? 'Tokenised' : skip ? 'Skipped' : 'Error'}
        </span>
      </div>`;

    if (ok) {
      const piiCount  = (r.pii  || []).length;
      const tokCount  = Object.keys(r.tokens || {}).length;
      const faceCount = r.faces || 0;

      body += `
        <div class="rc-stats">
          <div class="rc-stat">PII detected: <strong>${piiCount}</strong></div>
          <div class="rc-stat">Vault tokens: <strong>${tokCount}</strong></div>
          ${faceCount ? `<div class="rc-stat">Faces blurred: <strong>${faceCount}</strong></div>` : ''}
        </div>`;

      // Token list
      if (tokCount) {
        body += `<div class="token-list"><div class="token-scroll">`;
        const tokens = r.tokens || {};
        const piiMap = Object.fromEntries((r.pii || []).map(p => [p.text, p.label]));
        Object.entries(tokens).forEach(([origVal, tokId]) => {
          const label = piiMap[origVal] || '?';
          body += `
            <div class="token-item">
              <span class="tok-label">${esc(label)}</span>
              <span class="tok-id">&lt;&lt;${esc(tokId)}&gt;&gt;</span>
              <span class="tok-orig">${esc(origVal.substring(0, 28))}${origVal.length > 28 ? '…' : ''}</span>
              <button class="tok-copy" onclick="copyTok('${esc(tokId)}', this)">Copy ID</button>
            </div>`;
        });
        body += `</div></div>`;
      }

      if (r.downloads) {
        body += `<div class="rc-downloads">`;
        if (r.downloads.pdf)
          body += `<a class="dl-btn" href="${r.downloads.pdf}" download>⬇ Tokenised PDF</a>`;
        if (r.downloads.txt)
          body += `<a class="dl-btn" href="${r.downloads.txt}" download>⬇ Tokenised Text</a>`;
        if (r.downloads.image)
          body += `<a class="dl-btn" href="${r.downloads.image}" download>⬇ Tokenised Image</a>`;
        body += `</div>`;
      }
    } else if (r.status === 'error') {
      body += `<pre style="font-size:.7rem;color:var(--red);white-space:pre-wrap">${esc(r.reason || '')}</pre>`;
    } else {
      body += `<p style="font-size:.8rem;color:var(--text2)">${esc(r.reason || '')}</p>`;
    }

    card.innerHTML = body;
    resultsGrid.appendChild(card);
  });

  if (data.report_link) {
    reportLink.href = data.report_link;
    reportRow.style.display = 'block';
  }

  resultsSection.style.display = 'block';
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Load RBAC table
  loadRbac();
}

// ── Copy token ID ─────────────────────────────────────────────────────────
function copyTok(id, btn) {
  navigator.clipboard.writeText(id).then(() => {
    const prev = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = prev, 1500);
  });
}

// ── Role chips ────────────────────────────────────────────────────────────
if (roleChips) {
  roleChips.querySelectorAll('.role-chip').forEach(btn => {
    btn.addEventListener('click', () => {
      roleChips.querySelectorAll('.role-chip').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeRole = btn.dataset.role;
    });
  });
}

// ── Vault demo — decrypt ──────────────────────────────────────────────────
if (decryptBtn) {
  decryptBtn.addEventListener('click', async () => {
    const sid   = demoSession.value.trim();
    const tok   = demoToken.value.trim();
    const role  = activeRole;

    if (!sid || !tok || !role) {
      termPrint([
        { cls: 'error',     text: '// Error: fill in session, token and role' }
      ]);
      return;
    }

    termPrint([
      { cls: 'comment',    text: `// Requesting decryption…` },
      { cls: 'token-line', text: `role       = "${role}"` },
      { cls: 'token-line', text: `token_id   = "${tok}"` },
      { cls: 'dim',        text: `vault      = ${sid.substring(0,12)}…` },
      { cls: '',           text: '' },
    ]);

    let data;
    try {
      const res = await fetch('/api/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sid, token_id: tok, role })
      });
      data = await res.json();
    } catch (err) {
      termPrint([{ cls: 'error', text: `// Network error: ${err.message}` }]);
      return;
    }

    if (data.denied || data.error) {
      termPrint([
        { cls: 'error', text: `// ❌ ACCESS DENIED` },
        { cls: 'error', text: `// Role "${role}" may not view this token.` },
        { cls: 'dim',   text: `// Other locked fields remain secure.` },
      ]);
    } else {
      termPrint([
        { cls: 'success', text: `// ✓ DECRYPTION SUCCESSFUL` },
        { cls: 'success', text: `// Role "${role}" is authorised` },
        { cls: '',        text: '' },
        { cls: 'gold',    text: `plaintext = "${data.value}"` },
        { cls: '',        text: '' },
        { cls: 'comment', text: `// All other tokens remain locked.` },
      ]);
    }
  });
}

function termPrint(lines) {
  if (!termBody) return;
  termBody.innerHTML = '';
  lines.forEach(({ cls, text }) => {
    const d = document.createElement('div');
    d.className = `term-line ${cls}`;
    d.textContent = text;
    termBody.appendChild(d);
  });
}

// ── RBAC table ────────────────────────────────────────────────────────────
async function loadRbac() {
  const tbody = document.getElementById('rbacBody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/rbac');
    const data = await res.json();

    // Collect all labels
    const allLabels = new Set();
    Object.values(data).forEach(perms => perms.forEach(p => allLabels.add(p)));
    const labels = [...allLabels].sort();
    const roles  = ['doctor', 'auditor', 'legal_team', 'analyst', 'admin'];

    tbody.innerHTML = '';
    labels.forEach(lbl => {
      const tr = document.createElement('tr');
      let html = `<td>${esc(lbl)}</td>`;
      roles.forEach(r => {
        const perms = data[r] || [];
        const can   = perms.includes('ALL') || perms.includes(lbl);
        html += `<td class="${can ? 'rbac-yes' : 'rbac-no'}">${can ? '✓' : '—'}</td>`;
      });
      tr.innerHTML = html;
      tbody.appendChild(tr);
    });
  } catch (e) { /* silently ignore */ }
}
// Load RBAC on page init too
loadRbac();

// ── Loading ───────────────────────────────────────────────────────────────
const loadMsgs = [
  'Extracting text from files…',
  'Running PII detection (regex + NLP)…',
  'Encrypting values with AES-256-GCM…',
  'Storing tokens in vault database…',
  'Generating tokenised documents…',
  'Writing audit report…',
];
let loadInterval;

function showLoading(show) {
  loadingOverlay.style.display = show ? 'flex' : 'none';
  if (show) processBtn.disabled = true;
  else {
    clearInterval(loadInterval);
    processBtn.disabled = selectedFiles.length === 0;
  }
}
function animateLoading() {
  let i = 0;
  loadingSub.textContent = loadMsgs[0];
  loadInterval = setInterval(() => {
    i = (i + 1) % loadMsgs.length;
    loadingSub.textContent = loadMsgs[i];
  }, 1600);
}

// ── Utilities ─────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fmtSize(b) {
  if (b < 1024)       return b + ' B';
  if (b < 1048576)    return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}
