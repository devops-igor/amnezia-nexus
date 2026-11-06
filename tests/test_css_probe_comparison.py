"""Exercise the emitted CSS oracle JavaScript in Node, without a browser."""

import ast
import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_css_probe_comparison_in_node():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the pure JavaScript oracle check")
    source = Path(__file__).parent / "e2e" / "test_css_differential.py"
    # Read constants without importing Playwright or collecting the E2E suite.
    tree = ast.parse(source.read_text(encoding="utf-8"))
    scripts = {
        target.id: ast.literal_eval(statement.value)
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        for target in statement.targets
        if isinstance(target, ast.Name)
        and target.id in {"PROBE_SCRIPT", "COMPARE_SCRIPT"}
    }
    harness = r"""
const assert = require('node:assert/strict');
const {PROBE_SCRIPT, COMPARE_SCRIPT} = JSON.parse(process.argv[1]);
const probe = (0, eval)('(' + PROBE_SCRIPT + ')');
const compare = (0, eval)('(' + COMPARE_SCRIPT + ')');
assert.equal(typeof probe, 'function');
assert.equal(typeof compare, 'function');
const root = {tagName: 'HTML', id: '', className: ''};
const body = {tagName: 'BODY', id: '', className: '', querySelectorAll: () => [child]};
const child = {tagName: 'DIV', id: 'sample', className: 'card  active'};
global.document = {documentElement: root, body};
const properties = ['color', '--custom', 'width'];
const values = ['rgb(0, 0, 0)', 'full;value=preserved', '123px'];
let mutations = new Map();
let calls = 0;
global.getComputedStyle = (element, pseudo) => {
  calls++;
  const key = element.tagName + (pseudo || '');
  return Object.assign([...properties], {
    getPropertyValue: name =>
      mutations.has(key + name) ? mutations.get(key + name) : values[properties.indexOf(name)]
  });
};
const baseline = probe();
assert.equal(calls, 9);
assert.deepEqual(baseline[2], [2, 'div#sample.card.active', Array(3).fill(
  'color=rgb(0, 0, 0);--custom=full;value=preserved;width=123px'
)]);
const original = JSON.stringify(baseline);
const run = () => compare({baseline, probeScript: PROBE_SCRIPT});
assert.deepEqual(run(), {baselineCount: 3, modularCount: 3, differences: []});
// Compare entire strings, including arbitrary properties and all pseudo-elements.
mutations = new Map([
  ['DIVwidth', '124px'],
  ['DIV::before--custom', 'changed'],
  ['DIV::aftercolor', 'red'],
  ['HTMLcolor', 'blue']
]);
assert.deepEqual(run(), {
  baselineCount: 3, modularCount: 3,
  differences: ['html', 'div#sample.card.active',
    'div#sample.card.active::before', 'div#sample.card.active::after']
});
assert.equal(JSON.stringify(baseline), original);
for (const children of [[], [child, child]]) {
  body.querySelectorAll = () => children;
  assert.deepEqual(run(), {
    baselineCount: 3, modularCount: 2 + children.length, differences: []
  });
}
// A count mismatch must remain distinguishable even for empty snapshots.
global.document = {documentElement: root, body: {...body, querySelectorAll: () => []}};
assert.deepEqual(compare({baseline: [], probeScript: PROBE_SCRIPT}), {
  baselineCount: 0, modularCount: 2, differences: []
});
console.log('CSS probe comparison checks passed');
"""
    result = subprocess.run(
        [node, "-e", harness, json.dumps(scripts)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CSS probe comparison checks passed" in result.stdout
