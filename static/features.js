(() => {
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  let busy = false;
  let chatMessages = [];

  try {
    chatMessages = JSON.parse(
      sessionStorage.getItem('sentinel-chat-history') || '[]'
    );
    if (!Array.isArray(chatMessages)) chatMessages = [];
  } catch {
    chatMessages = [];
  }

  chatMessages = chatMessages.filter(m =>
    m && ['user', 'assistant'].includes(m.role) &&
    typeof m.content === 'string'
  ).slice(-12);

  function saveHistory() {
    try {
      sessionStorage.setItem(
        'sentinel-chat-history',
        JSON.stringify(chatMessages.slice(-12))
      );
    } catch {}
  }

  function renderChat() {
    const list = $('chatMessages');
    list.innerHTML = '';

    if (!chatMessages.length) {
      list.innerHTML =
        '<div class="chat-welcome"><b>Hey! I’m your scan assistant. 👋</b>' +
        '<p>Run a scan, then ask me about your findings, files, processes, ' +
        'or network activity. I’ll use your scan as context.</p></div>';
      return;
    }

    chatMessages.forEach(m => {
      const item = document.createElement('div');
      item.className = 'chat-message ' + m.role;
      const label = document.createElement('strong');
      label.textContent = m.role === 'user' ? 'You' : 'Sentinel AI';
      const text = document.createElement('p');
      text.textContent = m.content;
      item.append(label, text);
      list.appendChild(item);
    });
    list.scrollTop = list.scrollHeight;
  }

  function setChatOpen(open) {
    $('chatPanel').classList.toggle('open', open);
    $('chatToggle').setAttribute('aria-expanded', String(open));
    $('chatPanel').setAttribute('aria-hidden', String(!open));
    if (open) $('chatInput').focus();
  }

  $('chatToggle').addEventListener('click', () => {
    setChatOpen(!$('chatPanel').classList.contains('open'));
  });
  $('chatClose').addEventListener('click', () => setChatOpen(false));

  $('chatClear').addEventListener('click', () => {
    if (!confirm('Clear this chat history?')) return;
    chatMessages = [];
    saveHistory();
    renderChat();
  });

  $('chatForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;

    if (!window.lastReportReady()) {
      alert('Please run a security assessment before chatting.');
      return;
    }

    const input = $('chatInput');
    const text = input.value.trim();
    if (!text) return;

    chatMessages.push({ role: 'user', content: text });
    chatMessages = chatMessages.slice(-12);
    saveHistory();
    renderChat();
    input.value = '';
    busy = true;
    $('chatSend').disabled = true;
    $('chatStatus').textContent = 'Thinking about your scan…';

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
        body: JSON.stringify({
          report: window.getLastScanReport(),
          messages: chatMessages
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Chat request failed.');

      chatMessages.push({ role: 'assistant', content: data.answer });
      chatMessages = chatMessages.slice(-12);
      saveHistory();
      renderChat();
      $('chatStatus').textContent = 'Connected · ' + (data.model || 'Local AI');
    } catch (error) {
      $('chatStatus').textContent = 'Could not get a response.';
      chatMessages.push({
        role: 'assistant',
        content: 'Sorry, I could not answer that: ' + error.message
      });
      chatMessages = chatMessages.slice(-12);
      saveHistory();
      renderChat();
    } finally {
      busy = false;
      $('chatSend').disabled = false;
      input.focus();
    }
  });

  function addDeleteButtons() {
    document.querySelectorAll('#files .file-item').forEach(item => {
      const pathNode = item.querySelector('p');
      if (!pathNode) return;

      const path = pathNode.textContent.trim();
      if (!path.startsWith('/') || item.querySelector('.delete-file-btn')) return;

      const actions = document.createElement('div');
      actions.className = 'file-actions';

      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'delete-file-btn';
      button.textContent = '🗑 Delete file';
      button.setAttribute('aria-label', 'Delete ' + path);
      button.addEventListener('click', async () => {
        if (button.disabled) return;

        const approved = confirm(
          'PERMANENTLY DELETE THIS FILE?\n\n' + path +
          '\n\nThis cannot be undone. Only continue if you have verified ' +
          'that this file is safe to remove.'
        );
        if (!approved) return;

        button.disabled = true;
        button.textContent = 'Deleting…';

        try {
          const response = await fetch('/api/delete-file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            cache: 'no-store',
            body: JSON.stringify({ path })
          });
          const data = await response.json();
          if (!response.ok) throw new Error(data.error || 'Delete failed.');

          // Remove duplicate displays and keep the in-memory report in sync.
          document.querySelectorAll('#files .file-item').forEach(row => {
            if (row.querySelector('p')?.textContent.trim() === path) {
              row.remove();
            }
          });

          const report = window.getLastScanReport();
          if (report?.storage) {
            for (const group of ['candidates', 'largest_files']) {
              report.storage[group] = (report.storage[group] || [])
                .filter(file => file.path !== path);
            }
            report.storage.total_candidate_count =
              report.storage.candidates.length;
          }

          const note = $('storageNote');
          note.textContent = 'File deleted: ' + path +
            '. Run a new scan to refresh the complete storage results.';
          $('notice').textContent = 'Deleted file: ' + path;
        } catch (error) {
          alert('Could not delete file: ' + error.message);
          button.disabled = false;
          button.textContent = '🗑 Delete file';
        }
      });

      actions.appendChild(button);
      item.appendChild(actions);
    });
  }

  // Existing scan function remains responsible for collecting/rendering data.
  const originalRunScan = window.runScan;
  if (typeof originalRunScan === 'function') {
    window.runScan = async function (...args) {
      await originalRunScan.apply(this, args);
      addDeleteButtons();
    };
  }

  renderChat();
  setChatOpen(false);

  // Refresh buttons after the original scan replaces the file-list markup.
  const files = $('files');
  new MutationObserver(addDeleteButtons).observe(files, { childList: true });

  // Re-scan results replace file entries, but should not erase the chat history.

  // Upload and statically inspect a file directly from the chat window.
  const fileInput = $('chatFileInput');
  const chooseFileButton = $('chooseChatFile');
  const analyzeFileButton = $('fileAnalyzeBtn');

  chooseFileButton.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    $('chatFileName').textContent = file
      ? `${file.name} (${(file.size / 1024).toFixed(1)} KB)`
      : 'No file selected';
  });

  analyzeFileButton.addEventListener('click', async () => {
    const file = fileInput.files[0];
    if (!file) {
      fileInput.click();
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      alert('This inspection feature currently accepts files up to 2 MiB.');
      return;
    }
    if (busy) {
      alert('Please wait for the current AI request to finish.');
      return;
    }

    busy = true;
    analyzeFileButton.disabled = true;
    chooseFileButton.disabled = true;
    $('chatStatus').textContent = 'Inspecting file with local AI…';
    setChatOpen(true);

    chatMessages.push({
      role: 'user',
      content: `Please inspect this uploaded file: ${file.name} (${file.size} bytes).`
    });
    chatMessages = chatMessages.slice(-12);
    saveHistory();
    renderChat();

    const data = new FormData();
    data.append('file', file, file.name);

    try {
      const response = await fetch('/api/inspect-file', {
        method: 'POST',
        body: data,
        cache: 'no-store'
      });
      const result = await response.json();

      if (!response.ok) {
        const evidence = result.evidence;
        const extra = evidence
          ? `\nSHA-256: ${evidence.sha256}\nDetected: ${evidence.signature_assessment}`
          : '';
        throw new Error((result.error || 'File inspection failed.') + extra);
      }

      const evidence = result.evidence || {};
      const summary =
        `FILE INSPECTION\n` +
        `Name: ${evidence.filename || file.name}\n` +
        `Size: ${evidence.size_bytes ?? file.size} bytes\n` +
        `SHA-256: ${evidence.sha256 || 'Unavailable'}\n` +
        `Signature: ${evidence.signature_assessment || 'Unknown'}\n\n` +
        result.answer;

      chatMessages.push({ role: 'assistant', content: summary });
      chatMessages = chatMessages.slice(-12);
      saveHistory();
      renderChat();
      $('chatStatus').textContent =
        'File inspected · ' + (result.model || 'Local AI');
    } catch (error) {
      chatMessages.push({
        role: 'assistant',
        content: 'I could not finish inspecting that file: ' + error.message
      });
      chatMessages = chatMessages.slice(-12);
      saveHistory();
      renderChat();
      $('chatStatus').textContent = 'File inspection failed';
    } finally {
      busy = false;
      analyzeFileButton.disabled = false;
      chooseFileButton.disabled = false;
    }
  });

})();