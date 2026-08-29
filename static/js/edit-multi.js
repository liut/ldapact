// Multi-value edit rows: add/remove without a full-page round trip.
(function () {
  'use strict';
  function addRow(button) {
    var group = document.getElementById(button.dataset.target);
    if (!group) return;
    var row = document.createElement('div');
    row.className = 'multi-row';
    var input = document.createElement('input');
    input.type = 'text';
    input.name = button.dataset.name;
    row.appendChild(input);
    var remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'remove-row';
    remove.setAttribute('aria-label', 'Remove a value');
    remove.textContent = '−';
    row.appendChild(remove);
    group.insertBefore(row, button);
    input.focus();
  }
  document.addEventListener('click', function (event) {
    var add = event.target.closest('.add-row');
    if (add) {
      event.preventDefault();
      addRow(add);
      return;
    }
    var remove = event.target.closest('.remove-row');
    if (remove) {
      var row = remove.closest('.multi-row');
      if (row && row.parentElement.querySelectorAll('.multi-row').length > 1) {
        row.remove();
      }
      return;
    }
    var del = event.target.closest('.delete-attr');
    if (del) {
      // Clear every control for this attribute so the submit produces an
      // empty value set → Delete change (MUST attributes have no such button).
      var name = del.getAttribute('data-name');
      document.querySelectorAll('[name="' + name + '"]').forEach(function (el) {
        el.value = '';
      });
      var group = document.getElementById('f-' + name + '-group');
      if (group) group.innerHTML = '';
      return;
    }
  });
})();
