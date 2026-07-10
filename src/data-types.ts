/**
 * data-types.ts — the `dt.*@v` registry (v0 seed).
 *
 * Canonical design: dreamtree `data-types.md`. The registry is AUTHORITATIVE and
 * FAIL-CLOSED — a record whose `data_type` is not here is rejected. `encrypted`
 * is derived from the type's PII class (not set per record); `kind` says whether
 * the type is a plain record (self/tool data) or a credential (a W3C VC that goes
 * through the verifier). Versions are immutable: `@2` is a new entry, never a
 * retcon of `@1`, so old payloads always parse.
 */
export interface DataTypeEntry {
  category: string
  encrypted: boolean // derived from PII class: PII / partial / credential / outcome / identity → true
  kind: 'record' | 'credential'
}

// Seeded from data-types.md §"The seed list (v0)". encrypted=true covers PII,
// partial (encrypt whole payload if any field is PII — v0 rule), and all
// credential/outcome/identity (encrypted-at-rest by owner-sovereignty default).
export const DATA_TYPES: Record<string, DataTypeEntry> = {
  // dt.skill.* — structured, non-PII
  'dt.skill.transferable@1': { category: 'skill', encrypted: false, kind: 'record' },
  'dt.skill.soft@1': { category: 'skill', encrypted: false, kind: 'record' },
  'dt.skill.knowledge@1': { category: 'skill', encrypted: false, kind: 'record' },
  // dt.story.* — free-text narrative (PII)
  'dt.story.soared@1': { category: 'story', encrypted: true, kind: 'record' },
  // dt.experience.* — partial (description may be PII) → encrypt
  'dt.experience@1': { category: 'experience', encrypted: true, kind: 'record' },
  'dt.experience.employment@1': { category: 'experience', encrypted: true, kind: 'record' },
  'dt.experience.education@1': { category: 'experience', encrypted: true, kind: 'record' },
  // dt.value.*
  'dt.value.work@1': { category: 'value', encrypted: false, kind: 'record' },
  'dt.value.life@1': { category: 'value', encrypted: false, kind: 'record' },
  'dt.value.compass_statement@1': { category: 'value', encrypted: true, kind: 'record' },
  // dt.flow.* — partial
  'dt.flow.activity@1': { category: 'flow', encrypted: true, kind: 'record' },
  // dt.career.*
  'dt.career.option@1': { category: 'career', encrypted: false, kind: 'record' },
  'dt.career.location@1': { category: 'career', encrypted: true, kind: 'record' },
  // dt.budget@1 — financial PII
  'dt.budget@1': { category: 'budget', encrypted: true, kind: 'record' },
  // dt.personality.*
  'dt.personality.mbti@1': { category: 'personality', encrypted: false, kind: 'record' },
  // dt.competency.*
  'dt.competency.score@1': { category: 'competency', encrypted: false, kind: 'record' },
  // dt.idea_tree@1 / dt.list@1 — partial
  'dt.idea_tree@1': { category: 'idea_tree', encrypted: true, kind: 'record' },
  'dt.list@1': { category: 'list', encrypted: true, kind: 'record' },
  // dt.profile.* — synthesized identity text (PII)
  'dt.profile.headline@1': { category: 'profile', encrypted: true, kind: 'record' },
  'dt.profile.summary@1': { category: 'profile', encrypted: true, kind: 'record' },
  'dt.profile.display_name@1': { category: 'profile', encrypted: true, kind: 'record' },
  'dt.profile.identity_story@1': { category: 'profile', encrypted: true, kind: 'record' },
  // dt.dashboard.life@1 (PII)
  'dt.dashboard.life@1': { category: 'dashboard', encrypted: true, kind: 'record' },
  // dt.artifact.* — Telekora living-instance artifacts (learner-app.md Wave 4;
  // one record per instance EVENT, source_ref = the instance anchor). Free-text
  // and people-list types encrypt; scores/selections over authored vocabularies
  // don't (mirrors response.quiz / personality.mbti).
  'dt.artifact.reflection@1': { category: 'artifact', encrypted: true, kind: 'record' },
  'dt.artifact.rating_set@1': { category: 'artifact', encrypted: false, kind: 'record' },
  'dt.artifact.list@1': { category: 'artifact', encrypted: true, kind: 'record' },
  'dt.artifact.ranking@1': { category: 'artifact', encrypted: true, kind: 'record' },
  'dt.artifact.selection@1': { category: 'artifact', encrypted: false, kind: 'record' },
  'dt.artifact.goal@1': { category: 'artifact', encrypted: true, kind: 'record' },
  'dt.artifact.checklist@1': { category: 'artifact', encrypted: true, kind: 'record' },
  'dt.artifact.journal@1': { category: 'artifact', encrypted: true, kind: 'record' },
  'dt.artifact.bucket_set@1': { category: 'artifact', encrypted: true, kind: 'record' },
  // dt.response.* — Telekora silent-wallet writes
  'dt.response.quiz@1': { category: 'response', encrypted: false, kind: 'record' },
  'dt.response.text@1': { category: 'response', encrypted: true, kind: 'record' },
  'dt.response.poll@1': { category: 'response', encrypted: false, kind: 'record' },
  'dt.response.assessment@1': { category: 'response', encrypted: false, kind: 'record' },
  // dt.credential.* / dt.attestation — W3C VCs, encrypted at rest
  'dt.credential.learner_response@1': { category: 'credential', encrypted: true, kind: 'credential' },
  'dt.credential.course_completion@1': { category: 'credential', encrypted: true, kind: 'credential' },
  'dt.attestation@1': { category: 'credential', encrypted: true, kind: 'credential' },
  // dt.outcome.* — outcomes are attestations (VCs); v0 binary (partial deferred)
  'dt.outcome.validated@1': { category: 'outcome', encrypted: true, kind: 'credential' },
  'dt.outcome.refuted@1': { category: 'outcome', encrypted: true, kind: 'credential' },
  // dt.identity.* — the human-as-key anchor
  'dt.identity.proof_of_personhood@1': { category: 'identity', encrypted: true, kind: 'credential' },
  'dt.identity.did_key@1': { category: 'identity', encrypted: true, kind: 'record' },
}

// guid:roots-datatypes-lookup
/** The registry entry for a data_type key, or undefined if unregistered. */
export function lookupDataType(key: string): DataTypeEntry | undefined {
  return DATA_TYPES[key]
}
