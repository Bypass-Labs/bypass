// A repeated response marker proves a behavior change, not a security impact.
// Invalid attempts against a synthetic identity or code likewise do not show
// that a real account or access code can be brute-forced. Keep these cases
// consistent in reports, replay, memory and remediation.
export const unverifiedResponseEffect = finding =>
  finding?.severity === 'unrated' &&
    /fresh-(?:positive-)?marker-controls/.test(finding?.rule ?? '') ||
  finding?.kind === 'rate-limit-auth-gate' &&
    ['login', 'access-gate'].includes(finding?.webProof?.mode);
