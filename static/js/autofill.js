/* Runtime for server-emitted autoFill fragments (R8).
   Token grammar: %var|start-end/modifier%
   - var: source field name (value looked up by field id)
   - start-end: 0-based substring slice (end exclusive); empty end = to end;
     negative indexes count from the end (JS slice semantics)
   - modifiers: u = uppercase, l = lowercase, d = digits only, U = code-point
     aware slicing (safe for astral characters)
   The server emits <script>LDAPAutofill.bind({source, target, template});</script>. */
(function (global) {
  "use strict";

  var TOKEN_RE = /%([^%|/]+)(?:\|([^%|/]*))?(?:\/([a-zA-Z]+))?%/g;

  function applyModifiers(value, mods) {
    if (!mods) return value;
    var out = value;
    for (var i = 0; i < mods.length; i++) {
      switch (mods[i]) {
        case "u": out = out.toUpperCase(); break;
        case "l": out = out.toLowerCase(); break;
        case "d": out = out.replace(/\D/g, ""); break;
      }
    }
    return out;
  }

  function codePoints(s) {
    return Array.from(s);
  }

  function sliceValue(value, spec, unicodeSafe) {
    var chars = unicodeSafe ? codePoints(value) : value.split("");
    var len = chars.length;
    if (!spec) return value;
    var start, end;
    if (spec.charAt(0) === "-" && spec.indexOf("-", 1) === -1) {
      // "-N" means the last N characters.
      start = -parseInt(spec.slice(1), 10);
      end = len;
    } else {
      var parts = spec.split("-");
      start = parts[0] === "" ? 0 : parseInt(parts[0], 10);
      end = parts.length > 1 && parts[1] !== "" ? parseInt(parts[1], 10) : len;
    }
    if (isNaN(start)) start = 0;
    if (isNaN(end)) end = len;
    if (start < 0) start = Math.max(len + start, 0);
    if (end < 0) end = Math.max(len + end, 0);
    if (end < start) end = start;
    if (end > len) end = len;
    var slice = chars.slice(start, end);
    return slice.join("");
  }

  function applyTemplate(template, values) {
    return template.replace(TOKEN_RE, function (match, name, spec, mods) {
      var key = Object.keys(values).find(function (k) {
        return k.toLowerCase() === name.toLowerCase();
      });
      var value = key === undefined ? "" : String(values[key]);
      var unicodeSafe = mods && mods.indexOf("U") !== -1;
      return applyModifiers(sliceValue(value, spec, unicodeSafe), mods);
    });
  }

  function bind(config) {
    if (!config || !config.target) return;
    var sources = config.sources || (config.source ? [config.source] : []);
    if (!sources.length) return;
    var els = sources.map(function (id) { return document.getElementById(id); });
    if (!els.every(function (el) { return !!el; })) return;
    function refresh() {
      var target = document.getElementById(config.target);
      if (!target) return;
      var values = {};
      els.forEach(function (el, i) {
        values[sources[i]] = el.value;
      });
      var filled = applyTemplate(config.template, values);
      if (filled !== "") target.value = filled;
    }
    els.forEach(function (el) {
      el.addEventListener("change", refresh);
    });
  }

  global.LDAPAutofill = {
    bind: bind,
    applyTemplate: applyTemplate
  };
})(window);
