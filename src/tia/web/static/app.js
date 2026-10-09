/* 画面の動き。表示の切り替え、コピー、選択の印、既読、ライブ更新。
   データは全部サーバーの部品として受け取り、ここでは HTML を組み立てない。進捗の数字だけは文字として書き込む。 */
(function () {
  'use strict';
  var root = document.documentElement;
  var tokenMeta = document.querySelector('meta[name="tia-token"]');
  var token = tokenMeta ? tokenMeta.content : '';
  var toastTimer = null;
  var listScroll = null;      // 一覧を描き直す前のスクロール位置
  var detailPending = false;  // 入力中に見送った詳細の描き直し

  function showToast(message, ok) {
    var box = document.getElementById('toast');
    if (!box) return;
    box.textContent = message;
    box.dataset.ok = ok === false ? 'false' : 'true';
    box.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { box.hidden = true; }, 3200);
  }

  function currentId() {
    var detail = document.querySelector('#pane .detail[data-id]');
    return detail ? detail.dataset.id : null;
  }

  function markSelected() {
    var id = currentId();
    document.querySelectorAll('.row[data-id]').forEach(function (row) {
      row.setAttribute('aria-selected', String(row.dataset.id === id));
    });
  }

  function markRead() {
    var detail = document.querySelector('#pane .detail[data-unread="1"]');
    if (!detail || !window.htmx) return;
    detail.dataset.unread = '0';
    // 背景の処理。通知は出さない（サーバーもトーストの指示を付けない）
    htmx.ajax('POST', '/incidents/' + detail.dataset.id + '/read', {
      source: detail, swap: 'none', headers: { 'X-TIA-Token': token }
    });
  }

  function refresh(url, target) {
    var el = document.querySelector(target);
    if (!window.htmx || !el) return;
    var full = url.indexOf('?') === -1 ? url + location.search : url + '&' + location.search.slice(1);
    if (target === '#list') listScroll = el.scrollTop;
    // source を部品ごとに分ける。同じ要素からの要求が重なると HTMX は後の 1 つしか残さないため
    htmx.ajax('GET', full, { source: el, target: el, swap: 'outerHTML' });
  }

  function typing() {
    var pane = document.getElementById('pane');
    if (!pane) return false;
    var active = document.activeElement;
    if (active && pane.contains(active) && /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName)) return true;
    return !!pane.querySelector('details.inline-form[open], #case-slot form');
  }

  function showStale(on) {
    var mark = document.getElementById('stale');
    if (mark) mark.hidden = !on;
  }

  function refreshDetail(id, force) {
    var shown = currentId();
    var pane = document.getElementById('pane');
    if (!shown || !pane || (id && String(id) !== shown)) return;
    if (!force && typing()) {
      // 入力中は描き直さない。更新があることだけを知らせる
      detailPending = true;
      showStale(true);
      return;
    }
    detailPending = false;
    showStale(false);
    htmx.ajax('GET', '/partials/incidents/' + shown, { source: pane, target: pane, swap: 'innerHTML' });
  }

  function applyProgress(data) {
    var info;
    try { info = JSON.parse(data || '{}'); } catch (err) { return; }
    if (!info || !info.id) return;
    document.querySelectorAll('[data-progress-for="' + info.id + '"]').forEach(function (el) {
      var meter = el.querySelector('i');
      if (meter) meter.style.setProperty('--p', info.percent + '%');
    });
    document.querySelectorAll('[data-progress-text="' + info.id + '"]').forEach(function (el) {
      var text = info[el.dataset.progressKind];
      if (typeof text === 'string') el.textContent = text;
    });
    var track = document.querySelector('#rail .track.run');
    if (track) track.style.setProperty('--p', info.percent + '%');
  }

  document.addEventListener('click', function (e) {
    var theme = e.target.closest('[data-theme-toggle]');
    if (theme) {
      var next = root.dataset.theme === 'dark' ? 'light' : 'dark';
      root.dataset.theme = next;
      try { localStorage.setItem('tia-theme', next); } catch (err) {}
      return;
    }
    var copy = e.target.closest('[data-copy]');
    if (copy) {
      var code = copy.closest('.cmd').querySelector('code').textContent;
      if (navigator.clipboard) navigator.clipboard.writeText(code).catch(function () {});
      var label = copy.querySelector('[data-label]');
      label.textContent = 'コピーしました';
      copy.classList.add('is-copied');
      setTimeout(function () { label.textContent = 'コピー'; copy.classList.remove('is-copied'); }, 1600);
      return;
    }
    var stale = e.target.closest('#stale');
    if (stale) {
      refreshDetail(null, true);
      return;
    }
    var close = e.target.closest('[data-close-case]');
    if (close) {
      var slot = document.getElementById('case-slot');
      if (slot) slot.innerHTML = '';
    }
  });

  document.body.addEventListener('htmx:afterSwap', function (e) {
    if (e.target && (e.target.id === 'pane' || e.target.closest('#pane'))) {
      detailPending = false;
      showStale(false);
      markSelected();
      markRead();
      if (matchMedia('(max-width: 860px)').matches) {
        var pane = document.getElementById('pane');
        if (pane) pane.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
    if (e.target && e.target.id === 'list') {
      markSelected();
      if (listScroll !== null) { e.target.scrollTop = listScroll; listScroll = null; }
    }
  });

  document.body.addEventListener('tia-toast', function (e) {
    var detail = e.detail || {};
    showToast(detail.message || '', detail.ok);
  });

  document.body.addEventListener('htmx:responseError', function (e) {
    var xhr = e.detail && e.detail.xhr;
    // サーバーが HX-Trigger でトーストを指示していれば、それが出ている。重ねない
    if (xhr && xhr.getResponseHeader && xhr.getResponseHeader('HX-Trigger')) return;
    showToast(xhr && xhr.status ? '操作を受け付けなかった（' + xhr.status + '）' : '操作を受け付けなかった', false);
  });

  document.body.addEventListener('htmx:sendError', function () {
    showToast('サーバーに届かない', false);
  });

  function connect() {
    if (!window.EventSource) return;
    var source = new EventSource('/events');
    var pending = {};
    function schedule(name, fn) {
      if (pending[name]) return;
      pending[name] = setTimeout(function () { delete pending[name]; fn(); }, 150);
    }
    source.addEventListener('rail', function () { schedule('rail', function () { refresh('/partials/rail', '#rail'); }); });
    source.addEventListener('band', function () { schedule('band', function () { refresh('/partials/band', '#band'); }); });
    source.addEventListener('list', function () { schedule('list', function () { refresh('/partials/list', '#list'); }); });
    source.addEventListener('health', function () { schedule('health', function () { refresh('/partials/health', '#health'); }); });
    // 進捗は数字だけを書き換える。部品は取り直さない
    source.addEventListener('progress', function (e) { applyProgress(e.data); });
    source.onmessage = function () {};
    source.onerror = function () { /* ブラウザが retry の間隔でつなぎ直す */ };
    // incident-番号 のイベントは名前が動的なので、表示中の 1 件だけを購読する
    var watching = null;
    function watch() {
      var id = currentId();
      if (id === watching) return;
      watching = id;
      if (!id) return;
      source.addEventListener('incident-' + id, function () {
        schedule('detail', function () { refreshDetail(id); });
      });
    }
    watch();
    document.body.addEventListener('htmx:afterSwap', watch);
  }

  // 入力を終えたら、見送っていた描き直しを行う
  document.addEventListener('focusout', function () {
    setTimeout(function () { if (detailPending && !typing()) refreshDetail(null, true); }, 50);
  });

  markSelected();
  markRead();
  connect();
})();
