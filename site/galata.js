// galata-vault docs: put the tower mark before the book title, and a link
// back to the landing page at the top of the sidebar. Loaded by book.toml
// (additional-js); the markup is the same logo as site/assets/logo.svg.
(function () {
  var MARK =
    '<svg viewBox="0 0 64 64" aria-hidden="true" focusable="false">' +
    '<circle cx="32" cy="4.2" r="1.6" fill="currentColor"></circle>' +
    '<path fill="currentColor" fill-rule="evenodd" d="M32 6.5L46.5 25.5H44.5V34H42V56H46V60H18V56H22V34H19.5V25.5H17.5ZM24.2 32V29.4A1.8 1.8 0 0 1 27.8 29.4V32ZM30.2 32V29.4A1.8 1.8 0 0 1 33.8 29.4V32ZM36.2 32V29.4A1.8 1.8 0 0 1 39.8 29.4V32ZM30.8 42V38.6A1.2 1.2 0 0 1 33.2 38.6V42ZM29.6 47.5A2.4 2.4 0 0 1 34.4 47.5A2.4 2.4 0 0 1 33.38 49.47L34.3 55H29.7L30.62 49.47A2.4 2.4 0 0 1 29.6 47.5Z"></path>' +
    '</svg>';

  function ready(fn) {
    if (document.readyState !== 'loading') fn();
    else document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    var title = document.querySelector('.menu-title');
    if (title && !title.querySelector('.gv-mark')) {
      var mark = document.createElement('span');
      mark.className = 'gv-mark';
      mark.innerHTML = MARK;
      title.insertBefore(mark, title.firstChild);
    }

    // path_to_root is set by mdBook on every page; the landing page sits one
    // level above the book (site/_build/index.html over site/_build/docs/).
    var root = (typeof window.path_to_root === 'string') ? window.path_to_root : '';
    var box = document.querySelector('.sidebar-scrollbox');
    if (box && !box.querySelector('.gv-home')) {
      var home = document.createElement('a');
      home.className = 'gv-home';
      home.href = root + '../';
      home.innerHTML = MARK + '<span>galata vault</span><small>docs</small>';
      box.insertBefore(home, box.firstChild);
    }
  });
})();
