"use strict";

// Unit tests for static/js/tree-keys.js (R18 ARIA tree keyboard navigation)
// using a minimal DOM shim sufficient for the script's behavior.
const assert = require("assert");

class FakeEl {
  constructor(tag, attrs = {}) {
    this.tagName = tag;
    this.attrs = { ...attrs };
    this.children = [];
    this.parentElement = null;
    this.listeners = {};
    this.focused = false;
  }

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
  }

  setAttribute(name, value) {
    this.attrs[name] = String(value);
  }

  appendChild(child) {
    child.parentElement = this;
    this.children.push(child);
  }

  addEventListener(type, fn) {
    this.listeners[type] = fn;
  }

  focus() {
    this.focused = true;
  }

  dispatchEvent(ev) {
    ev.dispatched = true;
    if (this.listeners[ev.type]) {
      this.listeners[ev.type](ev);
    }
    return true;
  }

  // Supports the selectors tree-keys.js actually uses.
  querySelector(selector) {
    if (selector === ':scope > [role="group"]') {
      return this.children.find((c) => c.getAttribute("role") === "group") || null;
    }
    if (selector === '[role="treeitem"]') {
      const found = findRole(this, "treeitem");
      return found || null;
    }
    if (selector === "a[href]") {
      return this.children.find((c) => c.tagName === "a" && c.getAttribute("href")) || null;
    }
    return null;
  }
}

function findRole(el, role) {
  for (const child of el.children) {
    if (child.getAttribute("role") === role) return child;
    const nested = findRole(child, role);
    if (nested) return nested;
  }
  return null;
}

class FakeEvent {
  constructor(type, opts = {}) {
    this.type = type;
    this.bubbles = !!opts.bubbles;
    this.cancelable = !!opts.cancelable;
    this.detail = opts.detail;
    this.dispatched = false;
    this.preventDefaultCalled = false;
  }
  preventDefault() {
    this.preventDefaultCalled = true;
  }
}

global.window = global;
global.CustomEvent = FakeEvent;
global.document = {
  readyState: "complete",
  querySelectorAll: () => [],
  addEventListener: () => {}
};

require("../../static/js/tree-keys.js");
const LDAPTree = global.window.LDAPTree;

function buildTree() {
  const tree = new FakeEl("ul", { role: "tree" });
  const item1 = new FakeEl("li", { role: "treeitem", "aria-expanded": "true" });
  const group = new FakeEl("ul", { role: "group" });
  const item1a = new FakeEl("li", { role: "treeitem" });
  const item1b = new FakeEl("li", { role: "treeitem" });
  group.appendChild(item1a);
  group.appendChild(item1b);
  item1.appendChild(group);
  const item2 = new FakeEl("li", { role: "treeitem", "aria-expanded": "false" });
  const item3 = new FakeEl("li", { role: "treeitem" });
  tree.appendChild(item1);
  tree.appendChild(item2);
  tree.appendChild(item3);
  return { tree, item1, item1a, item1b, item2, item3 };
}

function key(tree, target, key) {
  const ev = new FakeEvent("keydown");
  ev.target = target;
  ev.key = key;
  tree.listeners.keydown(ev);
  return ev;
}

// Flat order with item1 expanded: item1, item1a, item1b, item2, item3.
{
  const { tree, item1 } = buildTree();
  LDAPTree.initTree(tree);
  assert.strictEqual(item1.getAttribute("tabindex"), "0", "focused item gets tabindex 0");
  assert.strictEqual(item1.focused, true, "first item focused");
}

{
  const { tree, item1, item1a, item3 } = buildTree();
  LDAPTree.initTree(tree);
  key(tree, item1, "ArrowDown");
  assert.strictEqual(item1a.getAttribute("tabindex"), "0", "ArrowDown moves to first child");
  assert.strictEqual(item1.getAttribute("tabindex"), "-1", "old item loses tabindex");

  key(tree, item3, "Home");
  assert.strictEqual(item1.getAttribute("tabindex"), "0", "Home moves to first item");

  key(tree, item1, "End");
  assert.strictEqual(item3.getAttribute("tabindex"), "0", "End moves to last item");
}

{
  const { tree, item2, item1 } = buildTree();
  LDAPTree.initTree(tree);
  let loaded = false;
  LDAPTree.setLoader(() => { loaded = true; });

  key(tree, item2, "ArrowRight");
  assert.strictEqual(item2.getAttribute("aria-expanded"), "true", "ArrowRight expands");
  assert.strictEqual(loaded, true, "loader hook fired on expand");

  key(tree, item2, "ArrowLeft");
  assert.strictEqual(item2.getAttribute("aria-expanded"), "false", "ArrowLeft collapses expanded node");

  key(tree, item2, "ArrowLeft");
  assert.strictEqual(item1.getAttribute("tabindex"), "0", "ArrowLeft on collapsed item moves to parent");

  key(tree, item1, "ArrowLeft");
  assert.strictEqual(item1.getAttribute("aria-expanded"), "false", "ArrowLeft collapses expanded parent");
}

{
  const { tree, item2 } = buildTree();
  LDAPTree.initTree(tree);
  let activated = null;
  item2.addEventListener("treeitem-activate", (ev) => { activated = ev.detail.node; });
  const ev = key(tree, item2, "Enter");
  assert.strictEqual(ev.preventDefaultCalled, true, "Enter prevents default");
  assert.strictEqual(activated, item2, "Enter dispatches treeitem-activate with the node");
}

console.log("tree_keys_test.js: all assertions passed");
