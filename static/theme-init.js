(function() {
  var saved = localStorage.getItem('ts-theme');
  var theme = saved || 'light';
  document.documentElement.setAttribute('data-theme', theme);
})();
