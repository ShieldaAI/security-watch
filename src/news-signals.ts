import { mentions, SENTENCE_END } from './matching.js';
import type { NewsSignals, Severity } from './types.js';
import { cut, highest } from './util.js';

/**
 * What a news article states about one finding's subject, read without a model: a CVSS score, a
 * vendor's word rating, a report of exploitation, a public exploit. These only ever raise a
 * finding's priority; a missing or negated statement lowers and dismisses nothing.
 *
 * A statement counts for the subject only when it is tied to it: the nearest advisory identifier
 * before the statement in its sentence is the subject's (`CVE-X (CVSS score: 9.8)`, a list item
 * `CVE-X (CVSS score: 9.3) - text`); or the article cites no other identifier and the sentence names
 * the subject; or, for a score or rating, the article is about the subject alone and the sentence
 * cites nothing. "It scores all five 9.2" in an article about five flaws is not read.
 */
export interface SignalTarget {
  /** Advisory identifiers of the finding's event, in any spelling. */
  identifiers: string[];
  /** Inventory names the finding matched: package, product and keyword names. */
  names: string[];
}

const IDENTIFIER = /\b(?:CVE-\d{4}-\d{4,19}|GHSA-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4})\b/gi;
const normal = (id: string) => (/^cve-/i.test(id) ? id.toUpperCase() : id.toLowerCase());
/** At most this much of an article is read, and this many sentences. */
const MAX_TEXT = 40_000;
const MAX_SENTENCES = 2_000;
const EXCERPT = 160;
/** How far before a statement a hedging word counts. */
const HEDGE_WINDOW = 60;
/** How far after a report of exploitation its identifier may stand. */
const FOLLOWING_WINDOW = 160;

/** "CVSS score: 9.8", "CVSS v3.1 score of 9.8", "CVSSv4: 9.3", "CVSS 3.1 severity score of 8.1". */
const SCORE_AFTER =
  /^CVSS\s*(?:v(?:ersion)?\s*)?([234](?:\.[01])?)?\s*(?:\(\s*v?[234]\.[01]\s*\)\s*)?(?:[-:,\s]*(?:base|severity|risk|overall)\b)?(?:[-:,\s]*(score|rating)\b)?(?:\s+(?:of|is|was|at))?[\s:=]*(\d{1,2}(?:\.\d)?)(?![\d%]|\.\d)/i;
/** "9.2 CVSS rating", "9.2 out of 10 on CVSS 4.0", "rated 9.8/10 under the CVSS scale". */
const SCORE_BEFORE =
  /(?<![\d.])(\d{1,2}(?:\.\d)?)(?:\s*\/\s*10|\s+out of 10)?(?:\s+(?:on|under|in|with|using))?(?:\s+the)?\s+$/i;
/** The CVSS version right after "CVSS", when a score came before it ("on CVSS 4.0"). */
const VERSION_AFTER = /^CVSS\s*(?:v(?:ersion)?\s*)?([234]\.[01])(?!\.?\d)/i;
/** A vendor's own word rating: "Severity: moderate" (Apache), "rated the vulnerability Important". */
const RATINGS = [
  /\bseverity\s*:\s*(low|moderate|medium|important|high|critical)\b/i,
  /\brat(?:ed|es)\s+(?:(?:it|this|the\s+(?:flaw|vulnerability|bug|issue)|CVE-\d{4}-\d{4,19}|GHSA(?:-[a-z\d]{4}){3})\s+)?(?:as\s+)?(?:an?\s+)?(low|moderate|medium|important|high|critical)\b(?![-\s]*(?:risk|rated|severity))/i,
];
/** Statements that a subject is being exploited. Bound, not negated and not hedged to count. */
const EXPLOITED = new RegExp(
  [
    'exploited in (?:the wild|attacks?|real[- ]world attacks)',
    '(?:under|come under|subject to) (?:active )?(?:exploitation|attacks?)',
    'actively (?:being )?exploited',
    'active exploitation',
    'exploitation (?:attempts|activity)',
    'in-the-wild exploitation',
    'exploitation in the wild',
    '(?:detected|observed|confirmed|seen|reported) (?:active |in-the-wild )?exploitation',
    '(?:attackers|hackers|threat actors|adversaries|bad (?:guys|actors)|miscreants|criminals|crooks) (?:are |were |have been |had been |have |had )?(?:actively |now )?(?:exploiting|exploited|weaponi[sz]ing|abusing)',
    'used in (?:the wild|attacks|real[- ]world attacks)',
    '(?:is|are|was|were|being|been) (?:actively |now |still )?(?:being )?exploited',
    'added\\b.{0,160}?(?:Known Exploited Vulnerabilities|\\bKEV\\b)',
  ].join('|'),
  'i',
);
/**
 * Read only to recognise a denial ("not aware of attacks exploiting the flaw"). On its own it is
 * not a report: researchers publish "videos demonstrating attacks using" a flaw.
 */
const DENIED_ONLY = /\battacks? (?:exploiting|using|leveraging|targeting)/i;
/** Public exploit code: shown as a reason, it raises nothing. */
const PUBLIC_EXPLOIT =
  /proof[- ]of[- ]concept|\bPoC\b|exploit code|public(?:ly available)? exploits?\b|working exploits?\b|exploits? (?:is|was|were|has been|have been) (?:released|published)/i;
/** A sentence that denies what it states. Anywhere in the sentence: "no evidence ... exploited". */
const NEGATION =
  /\b(?:no|not|never|neither|nor|none|nothing|nobody|no one|without|unaware|yet to|absence|lack of)\b|n['’]t\b/i;
/** Words just before a statement that only suppose it: "could be exploited", "suspected to be exploiting". */
const HEDGE =
  /\b(?:could|may|might|can|would|should|if|potential(?:ly)?|possibl[ey]|suspect(?:ed|s)?|alleged(?:ly)?|claims?|likely|unconfirmed|whether|unless|expects?)\b/i;

function sentences(text: string): string[] {
  const out: string[] = [];
  for (const line of text.slice(0, MAX_TEXT).split(/\n+/)) {
    for (const sentence of line.split(SENTENCE_END)) {
      const trimmed = sentence.trim();
      if (trimmed) out.push(trimmed);
      if (out.length >= MAX_SENTENCES) return out;
    }
  }
  return out;
}

export function scoreLevel(score: number): Severity {
  return score >= 9
    ? 'critical'
    : score >= 7
      ? 'high'
      : score >= 4
        ? 'medium'
        : score > 0
          ? 'low'
          : 'unknown';
}
function ratingLevel(word: string): Severity {
  const value = word.toLowerCase();
  return value === 'critical'
    ? 'critical'
    : value === 'high' || value === 'important'
      ? 'high'
      : value === 'moderate' || value === 'medium'
        ? 'medium'
        : 'low';
}

/** Reads the articles for one finding. `undefined` when they state nothing about its subject. */
export function newsSignals(
  articles: readonly { title: string; description: string }[],
  target: SignalTarget,
): NewsSignals | undefined {
  const targets = new Set(target.identifiers.map(normal));
  const names = [...new Set(target.names.filter((name) => name.trim().length >= 3))];
  const signals: NewsSignals = {};
  for (const article of articles) {
    const text = `${article.title}\n${article.description}`;
    const cited = new Set((text.slice(0, MAX_TEXT).match(IDENTIFIER) ?? []).map(normal));
    // Every identifier the article cites is this finding's: a sentence naming the subject is about it.
    const singleSubject = [...cited].every((id) => targets.has(id));
    /**
     * An article about one subject: it cites one identifier, the finding's, or none and names the
     * subject in its title (ZDI: "ZDI-26-1037: (0Day) Acme Router ... Vulnerability"). A score or
     * rating in a sentence that cites nothing is about that subject ("The ZDI has assigned a CVSS
     * rating of 7.6", "CISA gives the flaw a CVSS score of 5.0"). Not used for exploitation.
     */
    const articleSubject = !singleSubject
      ? undefined
      : cited.size === 1
        ? [...cited][0]
        : cited.size === 0
          ? names.find((name) => mentions(article.title, name))
          : undefined;
    for (const sentence of sentences(text)) {
      if (sentence.endsWith('?')) continue; // "Is there a proof-of-concept available?"
      const ids = [...sentence.matchAll(IDENTIFIER)].map((m) => ({ at: m.index, id: normal(m[0]) }));
      const named = singleSubject && names.some((name) => mentions(sentence, name));
      /**
       * The nearest identifier before the statement. For a report of exploitation with none before
       * it, the first one shortly after it ("X has come under active exploitation ..., tracked as
       * CVE-A"); a score or rating comes after its identifier.
       */
      const bound = (at: number, following = false): string | undefined => {
        const nearest =
          ids.filter((item) => item.at < at).at(-1) ??
          (following ? ids.find((item) => item.at - at <= FOLLOWING_WINDOW) : undefined);
        if (nearest) return targets.has(nearest.id) ? nearest.id : undefined;
        if (ids.length) return undefined;
        return named ? names.find((name) => mentions(sentence, name)) : undefined;
      };
      const excerpt = () => cut(sentence.replace(/\s+/g, ' '), EXCERPT);

      for (const match of sentence.matchAll(/CVSS/gi)) {
        const at = match.index;
        const after = SCORE_AFTER.exec(sentence.slice(at, at + 80));
        let score: number | undefined;
        let version: string | undefined;
        if (after) {
          // "CVSS 4.0" names a version; it is a score only after "score" or "rating".
          const isVersion = !after[1] && !after[2] && /^[234]\.[01]$/.test(after[3]!);
          if (!isVersion) {
            score = Number(after[3]);
            version = after[1];
          }
        }
        if (score === undefined) {
          const before = SCORE_BEFORE.exec(sentence.slice(Math.max(0, at - 40), at));
          if (before) {
            score = Number(before[1]);
            version = VERSION_AFTER.exec(sentence.slice(at, at + 20))?.[1];
          }
        }
        if (score === undefined || !(score > 0 && score <= 10)) continue;
        const subject = bound(at) ?? (ids.length ? undefined : articleSubject);
        if (!subject) continue;
        if (!signals.cvss || score > signals.cvss.score)
          signals.cvss = {
            score,
            ...(version ? { version: version.includes('.') ? version : `${version}.x` } : {}),
            level: scoreLevel(score),
            subject,
            excerpt: excerpt(),
          };
      }

      for (const pattern of RATINGS) {
        const match = pattern.exec(sentence);
        if (!match) continue;
        // A "Severity:" field stands on a line of its own in Apache advisories.
        const subject = bound(match.index + match[0].length) ?? (ids.length ? undefined : articleSubject);
        if (!subject) continue;
        const level = ratingLevel(match[1]!);
        if (!signals.rating || highest(level, signals.rating.level) !== signals.rating.level)
          signals.rating = { level, word: match[1]!.toLowerCase(), subject, excerpt: excerpt() };
      }

      // A negation anywhere in the sentence voids it ("no evidence ... has been exploited"); a hedge
      // counts only just before the statement, since a merged sentence often goes on to "could".
      const hedged = (match: RegExpExecArray) =>
        HEDGE.test(sentence.slice(Math.max(0, match.index - HEDGE_WINDOW), match.index + match[0].length));
      const exploited = EXPLOITED.exec(sentence);
      const denied = NEGATION.test(sentence) ? (exploited ?? DENIED_ONLY.exec(sentence)) : null;
      if (denied) {
        const subject = bound(denied.index, true);
        if (subject) signals.no_known_exploitation ??= { subject, excerpt: excerpt() };
      } else if (exploited && !hedged(exploited)) {
        const subject = bound(exploited.index, true);
        if (subject) signals.exploitation ??= { subject, excerpt: excerpt() };
      }

      const exploit = PUBLIC_EXPLOIT.exec(sentence);
      if (exploit && !NEGATION.test(sentence) && !hedged(exploit)) {
        const subject = bound(exploit.index, true);
        if (subject) signals.public_exploit ??= { subject, excerpt: excerpt() };
      }
    }
  }
  return Object.keys(signals).length ? signals : undefined;
}

/** The level the signals give a finding, and one reason per signal, for the finding's reasons. */
export function signalLevel(signals: NewsSignals): { level: Severity; reasons: string[] } {
  const reasons: string[] = [];
  let level: Severity = 'unknown';
  if (signals.cvss) {
    level = highest(level, signals.cvss.level);
    reasons.push(
      `An article states CVSS ${signals.cvss.version ? `${signals.cvss.version} ` : ''}${signals.cvss.score} for ${signals.cvss.subject}; no advisory severity is available yet.`,
    );
  }
  if (signals.rating) {
    level = highest(level, signals.rating.level);
    reasons.push(`An article reports a "${signals.rating.word}" rating for ${signals.rating.subject}.`);
  }
  if (signals.exploitation) {
    level = highest(level, 'critical');
    reasons.push(
      `An article reports exploitation of ${signals.exploitation.subject}; not confirmed by a known-exploited catalog.`,
    );
  } else if (signals.no_known_exploitation)
    reasons.push(`An article says no exploitation of ${signals.no_known_exploitation.subject} is known.`);
  if (signals.public_exploit)
    reasons.push(`An article reports public exploit code for ${signals.public_exploit.subject}.`);
  return { level, reasons };
}
