'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { countFindings, readSarif, severityFromScore } = require('./security-report.js');

const FIXTURES = path.join(__dirname, 'fixtures');
const load = (name) => JSON.parse(fs.readFileSync(path.join(FIXTURES, name), 'utf8'));

// Fixtures are trimmed copies of real SARIF output produced by Grype v0.121.2
// (anchore/grype) and Trivy v0.76.2 (aquasec/trivy) against
// ghcr.io/nrosier/harbor-scanner-grype:latest (image scans) and this repo (fs scan).
// Expected values below were computed by hand from the rule properties.

test('Grype image SARIF: security-severity bands drive the counts', () => {
  const result = countFindings([load('grype-image-results.sample.sarif')]);
  // error:3 -> two rules with score >= 9.0 (critical) plus one >= 7.0 (high);
  // warning:2 -> medium; note:1 -> low.
  assert.deepEqual(result.bySeverity, { critical: 2, high: 1, medium: 2, low: 1 });
  assert.equal(result.total, 6);
  assert.equal(result.highOrCritical, 3);
});

test('Trivy image SARIF: security-severity bands drive the counts', () => {
  const result = countFindings([load('trivy-image-results.sample.sarif')]);
  assert.deepEqual(result.bySeverity, { critical: 0, high: 3, medium: 2, low: 1 });
  assert.equal(result.total, 6);
  assert.equal(result.highOrCritical, 3);
});

test('Trivy fs SARIF: medium and low only, so zero High/Critical', () => {
  const result = countFindings([load('trivy-results.sample.sarif')]);
  assert.deepEqual(result.bySeverity, { critical: 0, high: 0, medium: 2, low: 2 });
  assert.equal(result.highOrCritical, 0);
});

test('zero findings: Grype SARIF with no rules and no results', () => {
  const result = countFindings([load('grype-results.empty.sarif')]);
  assert.equal(result.total, 0);
  assert.equal(result.highOrCritical, 0);
});

test('summing across several reports adds the counts', () => {
  const result = countFindings([
    load('grype-image-results.sample.sarif'),
    load('trivy-image-results.sample.sarif'),
    load('grype-results.empty.sarif'),
  ]);
  assert.equal(result.total, 12);
  assert.equal(result.highOrCritical, 6);
});

test('a null entry (missing file) contributes nothing', () => {
  const result = countFindings([null, load('trivy-image-results.sample.sarif')]);
  assert.equal(result.highOrCritical, 3);
});

test('a document without runs contributes nothing', () => {
  assert.equal(countFindings([{ version: '2.1.0' }]).total, 0);
  assert.equal(countFindings([{ runs: [{}] }]).total, 0);
});

test('non-array input yields zero counts', () => {
  assert.equal(countFindings(undefined).total, 0);
});

test('score bands: >=9.0 critical, >=7.0 high, >=4.0 medium, else low', () => {
  assert.equal(severityFromScore('10.0'), 'critical');
  assert.equal(severityFromScore('9.0'), 'critical');
  assert.equal(severityFromScore('8.9'), 'high');
  assert.equal(severityFromScore('7.0'), 'high');
  assert.equal(severityFromScore('6.9'), 'medium');
  assert.equal(severityFromScore('4.0'), 'medium');
  assert.equal(severityFromScore('3.9'), 'low');
  assert.equal(severityFromScore('0.0'), 'low');
  assert.equal(severityFromScore(undefined), null);
  assert.equal(severityFromScore('n/a'), null);
});

test('fallback to a severity tag when security-severity is absent', () => {
  const doc = {
    runs: [{
      tool: { driver: { rules: [{ id: 'X-1', properties: { tags: ['vulnerability', 'CRITICAL'] } }] } },
      results: [{ ruleId: 'X-1', level: 'note' }],
    }],
  };
  assert.deepEqual(countFindings([doc]).bySeverity, { critical: 1, high: 0, medium: 0, low: 0 });
});

test('fallback to result level when neither score nor tag is present', () => {
  const doc = {
    runs: [{
      tool: { driver: { rules: [{ id: 'X-2' }] } },
      results: [{ ruleId: 'X-2', level: 'error' }, { ruleId: 'X-2', level: 'warning' }],
    }],
  };
  assert.deepEqual(countFindings([doc]).bySeverity, { critical: 0, high: 1, medium: 1, low: 0 });
});

test('a result with an unknown rule is classed by its level', () => {
  const doc = { runs: [{ tool: { driver: { rules: [] } }, results: [{ ruleId: 'nope', level: 'error' }] }] };
  assert.equal(countFindings([doc]).highOrCritical, 1);
});

// --- file reading (missing and malformed input) ---

function tmpFile(contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secreport-'));
  const file = path.join(dir, 'report.sarif');
  if (contents !== undefined) fs.writeFileSync(file, contents);
  return { file, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('readSarif: missing file returns ok=false and does not throw', () => {
  const r = readSarif(path.join(os.tmpdir(), 'definitely-not-here-' + process.pid + '.sarif'));
  assert.equal(r.ok, false);
  assert.match(r.error, /^missing/);
});

test('readSarif: malformed JSON returns ok=false and does not throw', () => {
  const { file, cleanup } = tmpFile('{"runs": [');
  try {
    const r = readSarif(file);
    assert.equal(r.ok, false);
    assert.match(r.error, /^malformed/);
  } finally {
    cleanup();
  }
});

test('readSarif: JSON without a runs array is malformed', () => {
  const { file, cleanup } = tmpFile('{"version":"2.1.0"}');
  try {
    assert.equal(readSarif(file).ok, false);
  } finally {
    cleanup();
  }
});

test('readSarif: valid file parses and feeds countFindings', () => {
  const { file, cleanup } = tmpFile(fs.readFileSync(path.join(FIXTURES, 'trivy-image-results.sample.sarif'), 'utf8'));
  try {
    const r = readSarif(file);
    assert.equal(r.ok, true);
    assert.equal(countFindings([r.data]).highOrCritical, 3);
  } finally {
    cleanup();
  }
});
