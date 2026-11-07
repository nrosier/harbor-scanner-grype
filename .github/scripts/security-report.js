'use strict';

// Counts vulnerability severities in SARIF reports produced by Grype and Trivy.
// Used by the scheduled step of .github/workflows/security-scan.yml.
// Dependency-free (Node built-ins only) so it can be unit-tested locally.
//
// Severity rule (verified against Grype v0.121.2 and Trivy v0.76.2 SARIF output):
//   1. rule.properties["security-severity"] (CVSS score, string) when present:
//        >= 9.0 -> critical, >= 7.0 -> high, >= 4.0 -> medium, otherwise low.
//   2. Otherwise a rule tag named CRITICAL, HIGH, MEDIUM or LOW (Trivy adds these).
//   3. Otherwise the result level, as a fallback: error -> high, warning -> medium,
//      note -> low. This over-counts "error" as high when no score is present.
// A result whose rule cannot be found is classed by its result level only.
// Only "critical" and "high" count toward the scheduled issue decision.

const fs = require('fs');

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const TAG_SEVERITIES = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
const LEVEL_SEVERITIES = { error: 'high', warning: 'medium', note: 'low' };

function severityFromScore(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  const score = Number.parseFloat(String(raw));
  if (Number.isNaN(score)) return null;
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

function severityFromTags(tags) {
  if (!Array.isArray(tags)) return null;
  for (const tag of tags) {
    const key = String(tag).toUpperCase();
    if (Object.prototype.hasOwnProperty.call(TAG_SEVERITIES, key)) return TAG_SEVERITIES[key];
  }
  return null;
}

function classify(result, rule) {
  const props = (rule && rule.properties) || {};
  const fromScore = severityFromScore(props['security-severity']);
  if (fromScore) return fromScore;
  const fromTags = severityFromTags(props.tags);
  if (fromTags) return fromTags;
  return LEVEL_SEVERITIES[result.level] || 'low';
}

// Returns a map of ruleId -> rule for one SARIF run.
function ruleIndex(run) {
  const rules = (run && run.tool && run.tool.driver && run.tool.driver.rules) || [];
  const byId = new Map();
  for (const rule of rules) {
    if (rule && rule.id) byId.set(rule.id, rule);
  }
  return { rules, byId };
}

function findRule(result, index) {
  if (result.ruleId && index.byId.has(result.ruleId)) return index.byId.get(result.ruleId);
  if (Number.isInteger(result.ruleIndex) && index.rules[result.ruleIndex]) {
    return index.rules[result.ruleIndex];
  }
  return undefined;
}

// countFindings(sarifObjects) -> { total, bySeverity: {critical, high, medium, low}, highOrCritical }
// sarifObjects: array of already-parsed SARIF documents. Entries that are null or
// have no runs (for example a missing or malformed file) contribute nothing.
function countFindings(sarifObjects) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0;
  for (const doc of Array.isArray(sarifObjects) ? sarifObjects : []) {
    const runs = doc && Array.isArray(doc.runs) ? doc.runs : [];
    for (const run of runs) {
      const index = ruleIndex(run);
      for (const result of (run && run.results) || []) {
        const severity = classify(result, findRule(result, index));
        bySeverity[severity] += 1;
        total += 1;
      }
    }
  }
  return {
    total,
    bySeverity,
    highOrCritical: bySeverity.critical + bySeverity.high,
  };
}

// readSarif(path) -> { ok: true, data } | { ok: false, error }
// Never throws: a missing or malformed file is reported to the caller.
function readSarif(path) {
  let text;
  try {
    text = fs.readFileSync(path, 'utf8');
  } catch (err) {
    return { ok: false, error: `missing: ${err.code || err.message}` };
  }
  try {
    const data = JSON.parse(text);
    if (!data || !Array.isArray(data.runs)) {
      return { ok: false, error: 'malformed: no runs array' };
    }
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: `malformed: ${err.message}` };
  }
}

module.exports = { countFindings, readSarif, severityFromScore, SEVERITIES };
