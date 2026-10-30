// A response that exceeds the capture limit was not examined. Keep it distinct
// from a scope refusal and from a negative security result.
// Model-selected requests may need a full JSON response for controls and
// binding. This matches the guarded requester's maximum; evidence excerpts
// and model feedback remain separately bounded.
export const MODEL_RESPONSE_BYTES = 16 * 1024 * 1024;
export const responseSizeLimited = response => response?.blocked === true &&
  /response exceeds size limit/i.test(String(response.reason ?? ''));

export const requestFailureVerdict = responses =>
  responses.some(response => response?.refused || response?.blocked && !responseSizeLimited(response)) ?
    'blocked' : 'inconclusive';

export const responseSizeReason = response => responseSizeLimited(response) ?
  'response exceeded the capture byte limit; content was not assessed' : null;
