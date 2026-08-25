/* ARIA tree view keyboard navigation (R18, W3C ARIA APG Tree View pattern).
   U5 wires the loader hook to htmx; this file stays transport-agnostic. */
(function (global) {
  "use strict";

  var loader = null;
  var activeTree = null;

  function flatten(tree) {
    var out = [];
    (function walk(el) {
      var children = el.children;
      for (var i = 0; i < children.length; i++) {
        var child = children[i];
        if (child.getAttribute && child.getAttribute("role") === "treeitem") {
          out.push(child);
          if (child.getAttribute("aria-expanded") === "true") {
            var group = child.querySelector(':scope > [role="group"]');
            if (group) walk(group);
          }
        }
      }
    })(tree);
    return out;
  }

  function parentItem(node) {
    var parent = node.parentElement;
    while (parent && parent !== activeTree) {
      if (parent.getAttribute && parent.getAttribute("role") === "treeitem") {
        return parent;
      }
      parent = parent.parentElement;
    }
    return null;
  }

  function groupOf(node) {
    var parent = node.parentElement;
    while (parent && parent !== activeTree) {
      if (parent.getAttribute && parent.getAttribute("role") === "group") {
        return parent;
      }
      parent = parent.parentElement;
    }
    return null;
  }

  function setFocus(node) {
    var items = flatten(activeTree);
    for (var i = 0; i < items.length; i++) {
      items[i].setAttribute("tabindex", items[i] === node ? "0" : "-1");
    }
    node.setAttribute("tabindex", "0");
    node.focus();
  }

  function expand(node) {
    node.setAttribute("aria-expanded", "true");
    var btn = node.querySelector(".tree-toggle");
    if (btn) btn.setAttribute("aria-expanded", "true");
    if (loader) loader(node);
  }

  function collapse(node) {
    node.setAttribute("aria-expanded", "false");
    var btn = node.querySelector(".tree-toggle");
    if (btn) btn.setAttribute("aria-expanded", "false");
  }

  function firstChild(node) {
    var group = node.querySelector(':scope > [role="group"]');
    if (!group) return null;
    return group.querySelector('[role="treeitem"]');
  }

  function activate(node) {
    var event = new CustomEvent("treeitem-activate", {
      bubbles: true,
      cancelable: true,
      detail: { node: node }
    });
    if (node.dispatchEvent(event)) {
      var link = node.querySelector('a[href]');
      if (link) link.click();
    }
  }

  function onKeydown(ev) {
    var node = ev.target;
    if (!node || node.getAttribute("role") !== "treeitem") return;
    var items = flatten(activeTree);
    var idx = items.indexOf(node);
    var handled = true;

    switch (ev.key) {
      case "ArrowDown":
        if (idx < items.length - 1) setFocus(items[idx + 1]);
        break;
      case "ArrowUp":
        if (idx > 0) setFocus(items[idx - 1]);
        break;
      case "ArrowRight":
        if (node.getAttribute("aria-expanded") === "false") {
          expand(node);
        } else {
          var first = firstChild(node);
          if (first) setFocus(first);
        }
        break;
      case "ArrowLeft":
        if (node.getAttribute("aria-expanded") === "true") {
          collapse(node);
        } else {
          var parent = parentItem(node);
          if (parent) setFocus(parent);
        }
        break;
      case "Home":
        if (items.length) setFocus(items[0]);
        break;
      case "End":
        if (items.length) setFocus(items[items.length - 1]);
        break;
      case "Enter":
      case " ":
        ev.preventDefault();
        activate(node);
        break;
      default:
        handled = false;
    }
    if (handled) ev.preventDefault();
  }

  function initTree(root) {
    if (!root) return;
    var tree = root.getAttribute("role") === "tree" ? root : root.querySelector('[role="tree"]');
    if (!tree) return;
    activeTree = tree;
    tree.addEventListener("keydown", onKeydown);
    var items = flatten(tree);
    if (!items.length) return;
    var focused = tree.querySelector('[tabindex="0"]') || items[0];
    setFocus(focused);
  }

  global.LDAPTree = {
    init: function () {
      var trees = document.querySelectorAll('[role="tree"]');
      for (var i = 0; i < trees.length; i++) {
        initTree(trees[i]);
      }
    },
    initTree: initTree,
    setLoader: function (fn) { loader = fn; },
    expand: expand,
    collapse: collapse
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", global.LDAPTree.init);
  } else {
    global.LDAPTree.init();
  }
})(window);
