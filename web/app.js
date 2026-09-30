const token = document.querySelector('meta[name="guard-token"]').content;
const $ = selector => document.querySelector(selector);
let toastTimer;
let latestInfo = null;
let shuttingDown = false;
function toast(text, error = false) {
  const box = $('#toast'); box.textContent = text;
  box.className = 'show' + (error ? ' error' : '');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => box.className = '', 7000);
}
async function api(path, data) {
  const options = data === undefined ? {} : {method: 'POST', headers: {'Content-Type':'application/json', 'X-Guard-Token':token}, body: JSON.stringify(data)};
  const response = await fetch('/api/' + path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || 'Request failed.');
  return body;
}
function bytes(number) {
  if (!Number.isFinite(number) || number <= 0) return '0 B';
  const unit = Math.min(Math.floor(Math.log(number) / Math.log(1024)), 4);
  return (number / Math.pow(1024, unit)).toFixed(unit ? 1 : 0) + ' ' + ['B','KiB','MiB','GiB','TiB'][unit];
}
function duration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0 || seconds > 604800) return '—';
  if (seconds < 60) return '< 1 min';
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ${Math.ceil(seconds % 3600 / 60)} min`;
  return `${Math.floor(seconds / 86400)} d ${Math.ceil(seconds % 86400 / 3600)} h`;
}
function stat(label, value) {
  const node = el('div', 'download-stat'); node.append(el('small', '', label), el('strong', '', value)); return node;
}
function usage(label, value) {
  $(label).textContent = value ? `${value.cpu.toFixed(1)}% · ${bytes(value.memory)}` : '—';
}
function el(tag, className, text) {
  const node = document.createElement(tag); node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function renderItem(item) {
  const box = el('article', 'download');
  const top = el('div', 'download-top');
  top.append(el('div', 'download-name', item.name));
  const status = {downloading:'Downloading',paused:'Paused',scanning:'Scanning',ready:'Scan clear',blocked:'Blocked',released:'Released'}[item.state] || item.state;
  top.append(el('div', 'badge ' + item.state, status)); box.append(top);
  const stats = el('div', 'download-stats');
  stats.append(stat('Downloaded', item.size ? `${bytes(item.downloaded ?? item.size * item.progress)} / ${bytes(item.size)}` : (item.state === 'downloading' ? 'Fetching metadata' : 'Unknown size')),
               stat('Peers', `${item.peers || 0} connected${item.active_peers ? ` · ${item.active_peers} active` : ''}`),
               stat('Speed', item.state === 'downloading' ? `${bytes(item.speed)}/s` : '—'),
               stat('Remaining', item.state === 'downloading' ? duration(item.eta) : '—'));
  box.append(stats);
  const description = item.report || 'Awaiting review';
  box.append(el('div', 'download-sub', description));
  const progress = el('div', 'progress');
  const fill = el('span'); fill.style.width = `${Math.round((item.progress || 0)*100)}%`; progress.append(fill); box.append(progress);
  if (item.state === 'downloading') {
    const button = el('button', 'pause', 'Pause'); button.type = 'button';
    button.onclick = async () => {
      button.disabled = true;
      try { await api('pause', {hash:item.hash}); toast('Download paused.'); await refresh(); }
      catch (error) { toast(error.message, true); button.disabled = false; }
    }; box.append(button);
  }
  if (item.state === 'paused') {
    const button = el('button', 'resume', 'Resume download ↗'); button.type = 'button';
    button.disabled = !latestInfo || latestInfo.vpn !== 'running' || !latestInfo.rpc;
    button.onclick = async () => {
      button.disabled = true;
      try { await api('resume', {hash:item.hash}); toast('Download resumed through the VPN.'); await refresh(); }
      catch (error) { toast(error.message, true); button.disabled = false; }
    }; box.append(button);
  }
  if (item.state === 'ready') {
    const button = el('button', 'release', 'Release to Downloads ↗'); button.type = 'button';
    button.onclick = async () => {
      if (!confirm(`Release "${item.name}" to Downloads?`)) return;
      button.disabled = true;
      try { const result = await api('release', {hash:item.hash}); toast('Released to ' + result.destination); await refresh(); }
      catch (error) { toast(error.message, true); button.disabled = false; }
    };
    box.append(button);
  }
  if (item.state === 'blocked') {
    const button = el('button', 'release retry', 'Retry scan ↻'); button.type = 'button';
    button.onclick = async () => {
      button.disabled = true;
      try { await api('retry', {hash:item.hash}); toast('Scanning again.'); await refresh(); }
      catch (error) { toast(error.message, true); button.disabled = false; }
    };
    box.append(button);
  }
  if (item.state !== 'scanning') {
    const button = el('button', 'remove', 'Remove from list'); button.type = 'button';
    button.onclick = async () => {
      if (!confirm(`Remove "${item.name}" and its quarantined copy? Released files in Downloads are kept.`)) return;
      button.disabled = true;
      try { await api('remove', {hash:item.hash}); toast('Removed from quarantine.'); await refresh(); }
      catch (error) { toast(error.message, true); button.disabled = false; }
    };
    box.append(button);
  }
  return box;
}
async function refresh() {
  if (shuttingDown) return;
  try {
    const info = await api('status');
    latestInfo = info;
    const connected = info.vpn === 'running' && info.rpc;
    $('#connection').className = 'connection ' + (connected ? 'online' : 'offline');
    $('#connection span').textContent = connected ? 'VPN CONNECTED' : 'VPN UNAVAILABLE';
    $('#vpn-dot').className = 'dot ' + (connected ? 'online' : 'offline');
    $('.vpn-state').className = 'vpn-state ' + (connected ? 'online' : 'offline');
    $('#vpn-label').textContent = connected ? 'Protected tunnel active' : 'VPN unavailable — download paused';
    $('#vpn-description').textContent = connected ? 'Torrent traffic is confined to WireGuard.' : 'Select a profile and connect to begin.';
    const selector = $('#profiles'), selected = selector.value || info.active;
    selector.replaceChildren();
    if (!info.profiles.length) selector.add(new Option('No profiles imported', ''));
    for (const profile of info.profiles) selector.add(new Option(profile.name, profile.id));
    if (selected && info.profiles.some(profile => profile.id === selected)) selector.value = selected;
    $('#apply').textContent = connected && selector.value !== info.active ? 'Switch' : 'Connect';
    $('#apply').disabled = !info.profiles.length || (connected && selector.value === info.active);
    $('#disconnect').disabled = info.vpn !== 'running';
    const scanning = info.torrents.some(torrent => torrent.state === 'scanning');
    $('#shutdown').disabled = scanning;
    $('#shutdown-note').textContent = scanning ? 'Wait for the virus scan to finish before shutting down.' : 'Downloads will pause and need manual resume next time.';
    $('#download-count').textContent = info.torrents.length;
    const list = $('#downloads'); list.replaceChildren();
    if (!info.torrents.length) list.append(el('div', 'empty', 'No downloads yet. Add a magnet link or torrent file to begin.'));
    for (const item of info.torrents.slice().reverse()) list.append(renderItem(item));
    const data = info.usage || {};
    usage('#usage-vpn', data.vpn); usage('#usage-torrent', data.torrent);
    usage('#usage-app', data.app); usage('#usage-scanner', data.scanner);
    if (!data.scanner) $('#usage-scanner').textContent = 'Idle';
    $('#usage-quarantine').textContent = data.quarantine == null ? '—' : bytes(data.quarantine);
    $('#usage-snapshots').textContent = data.snapshots == null ? '—' : bytes(data.snapshots);
    const down = info.torrents.reduce((sum, item) => sum + (item.speed || 0), 0);
    const up = info.torrents.reduce((sum, item) => sum + (item.upload_speed || 0), 0);
    $('#usage-network').textContent = `${bytes(down)}/s · ${bytes(up)}/s`;
  } catch { $('#connection span').textContent = 'APP UNAVAILABLE'; }
}
async function upload(file, route) {
  if (!file) return;
  const data = await new Promise((resolve, reject) => {
    const reader = new FileReader(); reader.onload = () => resolve(reader.result.split(',')[1]); reader.onerror = () => reject(new Error('Could not read file.'));
    reader.readAsDataURL(file);
  });
  const result = await api(route, route === 'import' ? {filename:file.name, data} : {data});
  toast(route === 'import' ? `Imported ${result.imported} WireGuard profile(s). Select one to connect.` : 'Torrent added to quarantine.');
  await refresh();
}
$('#magnet-form').onsubmit = async event => {
  event.preventDefault();
  try { await api('add', {magnet:$('#magnet').value.trim()}); $('#magnet').value = ''; toast('Torrent added to quarantine.'); await refresh(); }
  catch (error) { toast(error.message, true); }
};
$('#torrent-file').onchange = async event => {
  try { await upload(event.target.files[0], 'add'); } catch (error) { toast(error.message, true); } event.target.value = '';
};
$('#profile-file').onchange = async event => {
  try { await upload(event.target.files[0], 'import'); } catch (error) { toast(error.message, true); } event.target.value = '';
};
$('#apply').onclick = async () => {
  const button = $('#apply'); button.disabled = true; button.textContent = 'Connecting…';
  try { await api('apply', {id:$('#profiles').value}); toast('VPN profile applied. The client is starting.'); await refresh(); }
  catch (error) { toast(error.message, true); }
  finally { button.disabled = false; button.textContent = 'Connect'; }
};
$('#profiles').onchange = () => {
  if (!latestInfo) return;
  const connected = latestInfo.vpn === 'running' && latestInfo.rpc;
  $('#apply').disabled = connected && $('#profiles').value === latestInfo.active;
  $('#apply').textContent = connected ? 'Switch' : 'Connect';
};
async function stopServices(shutdown) {
  const active = latestInfo?.torrents.filter(item => item.state === 'downloading').length || 0;
  const action = shutdown ? 'Stop the VPN, torrent client, and app service?' : 'Disconnect the VPN and stop the torrent client?';
  const message = active ? `${action}\n\n${active} active download(s) will be paused and must be resumed manually.` : action;
  if (!confirm(message)) return;
  const button = $(shutdown ? '#shutdown' : '#disconnect');
  button.disabled = true; button.textContent = shutdown ? 'Shutting down…' : 'Disconnecting…';
  try {
    const result = await api(shutdown ? 'shutdown' : 'disconnect', {confirm_active:active > 0});
    if (shutdown) {
      shuttingDown = true;
      toast(`All app services stopped. ${result.paused} download(s) paused. You can close this window.`);
      setTimeout(() => window.close(), 900);
    } else {
      toast(`VPN disconnected. ${result.paused} download(s) paused.`); await refresh();
    }
  } catch (error) { toast(error.message, true); button.disabled = false; }
  finally { button.textContent = shutdown ? 'Safe shutdown ↗' : 'Disconnect'; }
}
$('#disconnect').onclick = () => stopServices(false);
$('#shutdown').onclick = () => stopServices(true);
const drop = $('#torrent-drop');
drop.ondragover = event => { event.preventDefault(); drop.classList.add('drag'); };
drop.ondragleave = () => drop.classList.remove('drag');
drop.ondrop = async event => {
  event.preventDefault(); drop.classList.remove('drag');
  try { await upload(event.dataTransfer.files[0], 'add'); } catch (error) { toast(error.message, true); }
};
refresh(); setInterval(refresh, 3500);
