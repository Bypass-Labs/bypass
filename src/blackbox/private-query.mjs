// One definition for credential-like query names across scope, recon, model context and evidence.
const CREDENTIAL_KEYS = new Set(['token', 'key', 'apikey', 'api_key', 'sig', 'signature', 'secret',
  'auth', 'session', 'code', 'password', 'access_token', 'id_token', 'authorization',
  'credential', 'credentials']);

export function credentialQueryKey(name) {
  let decoded = String(name);
  for (let pass = 0; pass < 2 && /%[0-9a-f]{2}/i.test(decoded); pass++) {
    try {decoded = decodeURIComponent(decoded);} catch {break;}
  }
  const normalized = decoded.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  return CREDENTIAL_KEYS.has(normalized) ||
    normalized.split(/[^a-z0-9]+/).some(part => CREDENTIAL_KEYS.has(part));
}

/** Mask credential-bearing query values in URLs embedded in log lines, source or response excerpts. */
export function maskCredentialParams(value) {
  return String(value).replace(/([?&;])([^=&#\s;?]{1,128})=([^&#\s;"'<>]*)/g,
    (whole, separator, key) => {
      const decoded = [...new URLSearchParams(`${key}=`).keys()][0] ?? '';
      return credentialQueryKey(decoded) ? `${separator}${key}=[REDACTED]` : whole;
    });
}
