// Shared by the live runner and the sealed proof runtime. This helper compares
// only observed JSON objects; it never labels an LLM assertion as evidence.
const field = value => typeof value === 'string' &&
  /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(value);
const pointer = value => value === '' || typeof value === 'string' &&
  /^(?:\/(?:[A-Za-z_][A-Za-z0-9_.-]{0,63}|[0-9]{1,3})){1,3}$/.test(value);
const path = value => typeof value === 'string' && value.startsWith('/') &&
  !value.startsWith('//') && value.length <= 300 &&
  !/[\\;%?#{}]/.test(value) && !/[^\x21-\x7e]/.test(value) &&
  !value.split('/').some(part => part === '.' || part === '..');
const value = item => typeof item === 'string' &&
  item.length <= 256 && /^[\x20-\x7e]*$/.test(item) &&
  !/[;`$<>|&\\]/.test(item) &&
  !/(?:https?:|file:|ftp:|gopher:|data:|bearer\s|password\s*=|api[_-]?key\s*=|secret\s*=|token\s*=)/i.test(item);
const record = item => item !== null && typeof item === 'object' && !Array.isArray(item);
const primitive = item => typeof item === 'string' && item.length > 0 && item.length <= 512 ||
  typeof item === 'number' && Number.isFinite(item) || typeof item === 'boolean';
// This oracle is copied into standalone proofs, so keep the scanner's 16 MiB
// response ceiling locally instead of importing another runtime file.
const RESPONSE_BYTES = 16 * 1024 * 1024;

/** Shape check for an observed anonymous input and an owner-only GET. */
export function validBoundaryShape(plan) {
  return boundaryShapeReason(plan) === null;
}

/** Refusal codes expose model/harness mismatches without persisting payloads. */
export function boundaryShapeReason(plan) {
  if (!plan || !path(plan.protectedPath) || !path(plan.subject?.path) ||
      plan.protectedPath === plan.subject.path) return 'paths';
  const post = plan.subject.method === 'POST' && plan.subject.placement === 'json';
  const get = plan.subject.method === 'GET' && plan.subject.placement === 'query';
  if (!(post || get) || !field(plan.subject.key)) return 'subject';
  if (
      !Array.isArray(plan.subject.fixedFields) || plan.subject.fixedFields.length > (get ? 0 : 3) ||
      plan.subject.fixedFields.some(item => !field(item?.field) ||
        item.field === plan.subject.key || !value(item.value)) ||
      new Set(plan.subject.fixedFields.map(item => item?.field)).size !==
        plan.subject.fixedFields.length) return 'fixed-fields';
  if (!pointer(plan.ownerPointer) || !pointer(plan.candidatePointer)) return 'pointers';
  if (!field(plan.identityField) || !Array.isArray(plan.matchFields) ||
      plan.matchFields.length < 2 || plan.matchFields.length > 8 ||
      new Set(plan.matchFields).size !== plan.matchFields.length ||
      !plan.matchFields.includes(plan.identityField) ||
      plan.matchFields.some(name => !field(name))) return 'match-fields';
  const values = [plan.controlValue, plan.firstValue, plan.secondValue];
  if (!values.every(value)) return 'values';
  if (new Set(values).size !== values.length) return 'duplicate-values';
  return null;
}

function atPointer(body, path) {
  if (typeof body === 'string' && Buffer.byteLength(body) > RESPONSE_BYTES) return null;
  let parsed;
  try {parsed = typeof body === 'string' ? JSON.parse(body) : body;}
  catch {return null;}
  for (const key of path ? path.slice(1).split('/') : []) {
    if (!(record(parsed) || Array.isArray(parsed)) || !Object.hasOwn(parsed, key)) return null;
    parsed = parsed[key];
  }
  return parsed;
}

/** Compare at least two stable primitive fields against the owner-only item. */
export function boundaryMatch(ownerBody, candidateBody, plan) {
  const empty = {match: false, ownerValid: false, candidateCount: 0};
  if (!validBoundaryShape(plan)) return empty;
  const owner = atPointer(ownerBody, plan.ownerPointer);
  if (!record(owner) ||
      plan.matchFields.some(name => !primitive(owner[name]))) return empty;
  const candidate = atPointer(candidateBody, plan.candidatePointer);
  const rows = Array.isArray(candidate) ? candidate : [candidate];
  if (rows.length > 1000) return {...empty, ownerValid: true};
  return {match: rows.some(row => record(row) && plan.matchFields.every(name =>
    primitive(row[name]) && Object.is(row[name], owner[name]))),
  ownerValid: true, candidateCount: rows.filter(record).length};
}
