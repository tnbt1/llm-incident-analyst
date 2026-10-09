/* 描画の前に表示の明暗を決める。URL の ?theme=light|dark、保存した選択、OS の設定の順に優先する。
   head の中で同期的に読み込む。外部へは通信しない。 */
(function () {
  var saved = null;
  var asked = null;
  try { asked = new URLSearchParams(location.search).get('theme'); } catch (e) {}
  if (asked === 'light' || asked === 'dark') saved = asked;
  else { try { saved = localStorage.getItem('tia-theme'); } catch (e) {} }
  var dark = saved ? saved === 'dark' : (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
})();
