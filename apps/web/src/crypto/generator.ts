// Local password generator. Not a "crypto primitive" in the AEAD/KDF/
// OPAQUE sense (it never touches vault key material) — it's random string
// generation for the user to optionally use as a new item's password. Uses
// crypto.getRandomValues (the Web Crypto CSPRNG), never Math.random.

export interface GeneratorOptions {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
}

export const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions = {
  length: 20,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
};

const CHARSETS = {
  upper: "ABCDEFGHJKLMNPQRSTUVWXYZ", // no ambiguous I/O
  lower: "abcdefghijkmnopqrstuvwxyz", // no ambiguous l
  digits: "23456789", // no ambiguous 0/1
  symbols: "!@#$%^&*()-_=+[]{}",
} as const;

/** Returns a uniformly-random index in [0, max) using rejection sampling
 * over crypto.getRandomValues, so the result is not modulo-biased. */
function randomIndex(max: number): number {
  if (max <= 0) throw new Error("randomIndex: max must be positive");
  const range = 256 - (256 % max);
  const buffer = new Uint8Array(1);
  let value: number;
  do {
    crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= range);
  return value % max;
}

/** Generates a password from the selected character classes. At least one
 * class must be enabled and length must be positive, or this throws —
 * there is no silent fallback to a weaker default. When more than one
 * class is enabled, the result is guaranteed to contain at least one
 * character from each enabled class (Fisher-Yates-shuffled, so the
 * guaranteed characters aren't predictably placed at the front). */
export function generatePassword(options: Partial<GeneratorOptions> = {}): string {
  const opts = { ...DEFAULT_GENERATOR_OPTIONS, ...options };
  if (opts.length < 1) throw new Error("generatePassword: length must be at least 1");
  const classes = (["upper", "lower", "digits", "symbols"] as const).filter((c) => opts[c]);
  if (classes.length === 0) throw new Error("generatePassword: at least one character class must be enabled");
  if (opts.length < classes.length) {
    throw new Error("generatePassword: length must be at least the number of enabled character classes");
  }

  const alphabet = classes.map((c) => CHARSETS[c]).join("");
  const chars: string[] = [];
  // One guaranteed character per enabled class first.
  for (const cls of classes) {
    const set = CHARSETS[cls];
    chars.push(set[randomIndex(set.length)]);
  }
  // Fill the rest from the combined alphabet.
  while (chars.length < opts.length) {
    chars.push(alphabet[randomIndex(alphabet.length)]);
  }
  // Fisher-Yates shuffle so guaranteed characters aren't always at index 0..n.
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
