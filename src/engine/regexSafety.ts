const MAX_CUSTOM_REGEX_LENGTH = 120;
export const SAFE_REGEX_TIME_BUDGET_MS = 40;
export const SAFE_REGEX_MAX_MATCHES = 2000;

interface RegexGroupFrame {
  hasQuantifier: boolean;
  hasAlternation: boolean;
}

function checkStaticRegexDisallowList(pattern: string): string | null {
  if (pattern.length > MAX_CUSTOM_REGEX_LENGTH) {
    return 'Custom RegExp exceeds 120-character safety limit.';
  }
  if (/\\[1-9]/.test(pattern)) {
    return 'Potential ReDoS: backreferences are disallowed in custom RegExp rules.';
  }
  if (/\(\?[=!<]/.test(pattern)) {
    return 'Potential ReDoS: lookaround assertions are disallowed in custom RegExp rules.';
  }
  if (/(\.\*|\.\+|\\s\*|\\w\+)\s*\1|(?:\.\*|\.\+){2}/.test(pattern)) {
    return 'Potential ReDoS: adjacent unbounded wildcards rejected.';
  }
  return null;
}

function closeGroupFrame(
  stack: RegexGroupFrame[],
  nextChar: string,
): string | null {
  const closed = stack.length > 1 ? stack.pop() : undefined;
  const frame = closed ?? { hasQuantifier: false, hasAlternation: false };
  const hasOuterQuantifier = nextChar === '+' || nextChar === '*' || nextChar === '{';

  if (hasOuterQuantifier && (frame.hasQuantifier || frame.hasAlternation)) {
    return 'Potential catastrophic backtracking (ReDoS) nested quantifier/alternation rejected.';
  }

  const parent = stack[stack.length - 1];
  if (parent) {
    if (hasOuterQuantifier || frame.hasQuantifier) {
      parent.hasQuantifier = true;
    }
    if (frame.hasAlternation) {
      parent.hasAlternation = true;
    }
  }
  return null;
}

function recordGroupToken(
  pattern: string,
  index: number,
  stack: RegexGroupFrame[],
): string | null {
  const ch = pattern.charAt(index);
  if (ch === '(') {
    stack.push({ hasQuantifier: false, hasAlternation: false });
    return null;
  }
  if (ch === ')') {
    return closeGroupFrame(stack, pattern.charAt(index + 1));
  }
  const top = stack[stack.length - 1];
  if (!top) return null;
  if (ch === '|') {
    top.hasAlternation = true;
    return null;
  }
  const isBraceQuantifier = ch === '{' && /^\{\d+(?:,\d*)?\}/.test(pattern.slice(index));
  const isSimpleQuantifier = ch === '+' || ch === '*' || (ch === '?' && pattern[index - 1] !== '(');
  if (isSimpleQuantifier || isBraceQuantifier) {
    top.hasQuantifier = true;
  }
  return null;
}

/**
 * Depth-aware static analyzer rejecting catastrophic backtracking (ReDoS),
 * nested quantifiers, quantified alternations, lookarounds, and backreferences.
 */
export function hasUnsafeRegexConstruct(pattern: string): string | null {
  const disallowedReason = checkStaticRegexDisallowList(pattern);
  if (disallowedReason) return disallowedReason;

  const stack: RegexGroupFrame[] = [{ hasQuantifier: false, hasAlternation: false }];
  let inCharClass = false;

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern.charAt(i);
    if (ch === '\\') {
      i += 1;
      continue;
    }
    if (inCharClass) {
      if (ch === ']') inCharClass = false;
      continue;
    }
    if (ch === '[') {
      inCharClass = true;
      continue;
    }
    const reason = recordGroupToken(pattern, i, stack);
    if (reason) return reason;
  }

  return null;
}
