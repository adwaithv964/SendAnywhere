(() => {
  const $ = (id) => document.getElementById(id);

  // -- DOM refs
  const fileInput       = $('fileInput');
  const chooseFiles     = $('chooseFiles');
  const keyInput        = $('keyInput');
  const receiveBtn      = $('receiveBtn');
  const status          = $('status');
  const sendModal       = $('sendModal');
  const resultModal     = $('resultModal');
  const receiveModal    = $('receiveModal');
  const textModal       = $('textModal');
  const textResultModal = $('textResultModal');
  const textReceiveModal= $('textReceiveModal');
  const fileList        = $('fileList');
  const startUpload     = $('startUpload');
  const progressWrap    = $('progressWrap');
  const progressBar     = $('progressBar');
  const progressText    = $('progressText');
  const resultKey       = $('resultKey');
  const resultExpiry    = $('resultExpiry');
  const resultFiles     = $('resultFiles');
  const receiveBody     = $('receiveBody');
  const textInput       = $('textInput');
  const textCharCount   = $('textCharCount');
  const textProgressWrap= $('textProgressWrap');
  const textProgressText= $('textProgressText');
  const textResultKey   = $('textResultKey');
  const textResultExpiry= $('textResultExpiry');
  const textReceiveBody = $('textReceiveBody');

  let selectedFiles = [];
  let currentKey = '';
  let currentTextKey = '';

  // -- Utilities
  const bytes = (n) => {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
  };

  function setStatus(message = '', kind = '') {
    status.textContent = message;
    status.className = `status${kind ? ` ${kind}` : ''}`;
  }

  function openModal(el) {
    el.classList.remove('hidden');
    el.setAttribute('aria-hidden', 'false');
  }
  function closeModal(el) {
    el.classList.add('hidden');
    el.setAttribute('aria-hidden', 'true');
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>'"]/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
  }

  // -- Tab switching
  $('tabFiles').addEventListener('click', () => switchTab('files'));
  $('tabText').addEventListener('click',  () => switchTab('text'));

  function switchTab(tab) {
    const isFiles = tab === 'files';
    $('tabFiles').classList.toggle('active', isFiles);
    $('tabText').classList.toggle('active', !isFiles);
    $('tabFiles').setAttribute('aria-selected', String(isFiles));
    $('tabText').setAttribute('aria-selected', String(!isFiles));
    $('panelFiles').classList.toggle('hidden', !isFiles);
    $('panelText').classList.toggle('hidden', isFiles);
  }

  // -- File send flow
  function renderSelected() {
    fileList.innerHTML = selectedFiles.map(file => `
      <div class="file-item">
        <div class="file-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</div>
        <div class="file-size">${bytes(file.size)}</div>
      </div>`).join('');
  }

  chooseFiles.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    selectedFiles = Array.from(fileInput.files || []);
    fileInput.value = '';
    if (!selectedFiles.length) return;
    renderSelected();
    progressWrap.classList.add('hidden');
    startUpload.disabled = false;
    startUpload.textContent = 'Create transfer key';
    openModal(sendModal);
  });

  $('closeSend').addEventListener('click', () => closeModal(sendModal));
  $('closeResult').addEventListener('click', () => closeModal(resultModal));
  $('closeReceive').addEventListener('click', () => closeModal(receiveModal));
  document.querySelectorAll('.modal-backdrop').forEach(b =>
    b.addEventListener('click', e => closeModal(e.target.closest('.modal'))));

  startUpload.addEventListener('click', async () => {
    if (!selectedFiles.length) return;
    const form = new FormData();
    selectedFiles.forEach(file => form.append('files', file, file.name));
    startUpload.disabled = true;
    progressWrap.classList.remove('hidden');
    progressBar.style.width = '0%';
    progressText.textContent = 'Encrypting & uploading...';

    try {
      const result = await xhrUpload('/api/transfers', form, percent => {
        progressBar.style.width = `${percent}%`;
        progressText.textContent = `Encrypting & uploading... ${percent}%`;
      });
      currentKey = result.code;
      resultKey.textContent = result.code;
      resultExpiry.textContent = `Available for ${Math.max(1, Math.round((result.expiresAt - Date.now()) / 60000))} minutes`;
      resultFiles.innerHTML = result.files.map(file => `
        <div class="file-item"><div class="file-name">${escapeHtml(file.name)}</div><div class="file-size">${bytes(file.size)}</div></div>`).join('');
      closeModal(sendModal);
      openModal(resultModal);
      setStatus('Transfer ready. Share the 6-digit key.', 'success');
    } catch (err) {
      progressText.textContent = 'Upload failed.';
      startUpload.disabled = false;
      setStatus(err.message || 'Upload failed.', 'error');
    }
  });

  $('copyKey').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(currentKey);
      $('copyKey').textContent = 'Copied!';
      setTimeout(() => $('copyKey').textContent = 'Copy key', 1400);
    } catch {
      setStatus('Copy failed. Select and copy the key manually.', 'error');
    }
  });

  $('cancelTransfer').addEventListener('click', async () => {
    if (!currentKey) return;
    try { await fetch(`/api/transfers/${currentKey}`, { method: 'DELETE' }); } catch {}
    currentKey = '';
    closeModal(resultModal);
    setStatus('Transfer deleted.', 'success');
  });

  // -- Text send flow
  $('openTextSend').addEventListener('click', () => {
    textInput.value = '';
    textCharCount.textContent = '0 chars';
    textProgressWrap.classList.add('hidden');
    $('startTextSend').disabled = false;
    $('startTextSend').textContent = 'Create text key';
    openModal(textModal);
    textInput.focus();
  });

  textInput.addEventListener('input', () => {
    const len = textInput.value.length;
    const kb = (new Blob([textInput.value]).size / 1024).toFixed(1);
    textCharCount.textContent = `${len.toLocaleString()} chars - ${kb} KB`;
  });

  $('closeText').addEventListener('click', () => closeModal(textModal));
  $('closeTextResult').addEventListener('click', () => closeModal(textResultModal));
  $('closeTextReceive').addEventListener('click', () => closeModal(textReceiveModal));

  $('startTextSend').addEventListener('click', async () => {
    const text = textInput.value;
    if (!text.trim()) { setStatus('Text cannot be empty.', 'error'); return; }
    const btn = $('startTextSend');
    btn.disabled = true;
    textProgressWrap.classList.remove('hidden');
    textProgressText.textContent = 'Encrypting & sending...';

    try {
      const res = await fetch('/api/texts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ text })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Send failed.');

      currentTextKey = data.code;
      textResultKey.textContent = data.code;
      textResultExpiry.textContent = `Available for ${Math.max(1, Math.round((data.expiresAt - Date.now()) / 60000))} minutes - single-use`;
      closeModal(textModal);
      openModal(textResultModal);
      setStatus('Text ready. Share the 6-digit key.', 'success');
    } catch (err) {
      textProgressText.textContent = err.message || 'Send failed.';
      btn.disabled = false;
      setStatus(err.message || 'Send failed.', 'error');
    }
  });

  $('copyTextKey').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(currentTextKey);
      $('copyTextKey').textContent = 'Copied!';
      setTimeout(() => $('copyTextKey').textContent = 'Copy key', 1400);
    } catch {
      setStatus('Copy failed. Select and copy the key manually.', 'error');
    }
  });

  $('cancelTextTransfer').addEventListener('click', async () => {
    if (!currentTextKey) return;
    try { await fetch(`/api/texts/${currentTextKey}`, { method: 'DELETE' }); } catch {}
    currentTextKey = '';
    closeModal(textResultModal);
    setStatus('Text deleted.', 'success');
  });

  // -- Receive flow (auto-detects files vs text)
  receiveBtn.addEventListener('click', receive);
  keyInput.addEventListener('keydown', e => { if (e.key === 'Enter') receive(); });
  keyInput.addEventListener('input', () => {
    keyInput.value = keyInput.value.replace(/\D/g, '').slice(0, 6);
  });

  async function receive() {
    const code = keyInput.value.trim();
    if (!/^\d{6}$/.test(code)) {
      setStatus('Enter the 6-digit key.', 'error');
      keyInput.focus();
      return;
    }
    receiveBtn.disabled = true;
    setStatus('Looking for transfer...');

    try {
      // Try file transfer first
      const fileRes = await fetch(`/api/transfers/${code}`, { headers: { Accept: 'application/json' } });
      if (fileRes.ok) {
        const data = await fileRes.json();
        renderReceive(data);
        openModal(receiveModal);
        setStatus('Transfer found.', 'success');
        return;
      }

      // Try text transfer
      const textRes = await fetch(`/api/texts/${code}`, { headers: { Accept: 'application/json' } });
      if (textRes.ok) {
        const data = await textRes.json();
        renderTextReceive(data);
        openModal(textReceiveModal);
        setStatus('Text received.', 'success');
        return;
      }

      // Both failed
      const errData = await (fileRes.status === 410 ? fileRes : textRes).json().catch(() => ({}));
      throw new Error(errData.error || 'Transfer not found or expired.');
    } catch (err) {
      setStatus(err.message || 'Transfer unavailable.', 'error');
    } finally {
      receiveBtn.disabled = false;
    }
  }

  function renderReceive(data) {
    const expiryMinutes = Math.max(1, Math.round((data.expiresAt - Date.now()) / 60000));
    receiveBody.innerHTML = `
      <div class="enc-notice">
        <span class="enc-lock" aria-hidden="true">🔒</span>
        AES-256-GCM Encrypted · ${data.files.length} file${data.files.length === 1 ? '' : 's'} · ${bytes(data.totalBytes)} · expires in about ${expiryMinutes} min
      </div>
      <button class="primary" id="downloadAll">Download all</button>
      <div class="result-files">
        ${data.files.map(file => `
          <div class="file-item receive-row">
            <div class="filename"><div class="name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</div><small>${bytes(file.size)}</small></div>
            <button data-file-id="${escapeHtml(file.id)}" class="download-one">Download</button>
          </div>`).join('')}
      </div>`;

    $('downloadAll').addEventListener('click', () => downloadWithToken(data.code, null));
    receiveBody.querySelectorAll('.download-one').forEach(btn => {
      btn.addEventListener('click', () => downloadWithToken(data.code, btn.dataset.fileId));
    });
  }

  function renderTextReceive(data) {
    textReceiveBody.innerHTML = `
      <div class="enc-notice">
        <span class="enc-lock" aria-hidden="true">🔒</span>
        AES-256-GCM Encrypted · ${data.charCount.toLocaleString()} chars · single-use
      </div>
      <pre class="text-received" id="receivedText">${escapeHtml(data.text)}</pre>
      <button class="primary" id="copyReceivedText">Copy text</button>`;

    $('copyReceivedText').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(data.text);
        $('copyReceivedText').textContent = 'Copied!';
        setTimeout(() => $('copyReceivedText').textContent = 'Copy text', 1400);
      } catch {
        setStatus('Could not copy - select the text manually.', 'error');
      }
    });
  }

  async function downloadWithToken(code, fileId) {
    try {
      const body = fileId ? { fileId } : {};
      const tokenRes = await fetch(`/api/transfers/${code}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(body)
      });
      const tokenData = await tokenRes.json();
      if (!tokenRes.ok) throw new Error(tokenData.error || 'Could not get download token.');

      const url = fileId
        ? `/api/transfers/${code}/files/${fileId}?t=${encodeURIComponent(tokenData.token)}`
        : `/api/transfers/${code}/all?t=${encodeURIComponent(tokenData.token)}`;

      window.location.href = url;
    } catch (err) {
      setStatus(err.message || 'Download failed.', 'error');
    }
  }

  function xhrUpload(url, data, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      xhr.responseType = 'json';
      xhr.upload.onprogress = e => {
        if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
      };
      xhr.onload = () => {
        const body = xhr.response || {};
        if (xhr.status >= 200 && xhr.status < 300) resolve(body);
        else reject(new Error(body.error || `Upload failed (${xhr.status}).`));
      };
      xhr.onerror = () => reject(new Error('Network error while uploading.'));
      xhr.ontimeout = () => reject(new Error('Upload timed out.'));
      xhr.timeout = 0;
      xhr.send(data);
    });
  }
})();
