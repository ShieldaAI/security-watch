import test from 'node:test';
import assert from 'node:assert/strict';
import { newsSignals, signalLevel, scoreLevel } from '../dist/news-signals.js';

// Synthetic sentences written after the phrasings found in the 2026-11-19 news corpus (The Hacker
// News, Rapid7, Tenable, The Register, Security Affairs, ZDI, seclists). No article text is copied.
const A = 'CVE-2026-1001';
const B = 'CVE-2026-1002';
const read = (description, target = { identifiers: [A], names: [] }, title = 'Security update') =>
  newsSignals([{ title, description }], target);

test('stated CVSS scores in the forms articles use', async (t) => {
  for (const [text, score, version] of [
    [`The flaw, tracked as ${A} (CVSS score: 9.8), allows code execution.`, 9.8],
    [`The issue (${A}, CVSS score: 9.1) was fixed.`, 9.1],
    [`${A} has a CVSS score of 8.8.`, 8.8],
    [`${A} carries a CVSS v3.1 score of 7.5 according to the vendor.`, 7.5, '3.1'],
    [`${A} was assigned a CVSS 4.0 score of 9.2 by the researchers.`, 9.2, '4.0'],
    [`${A} has a CVSSv4: 9.3 rating.`, 9.3, '4.x'],
    [`${A} has a CVSS 3.1 severity score of 8.1.`, 8.1, '3.1'],
    [`The bug, ${A}, received a critical, 9.2 CVSS rating.`, 9.2],
    [`${A} scores 9.2 out of 10 on CVSS 4.0.`, 9.2, '4.0'],
    [`${A} is rated 9.8/10 under CVSS v3.1.`, 9.8, '3.1'],
    [`${A} (CVSS score of 10.0) is the worst.`, 10],
  ])
    await t.test(text, () => {
      const signals = read(text);
      assert.equal(signals?.cvss?.score, score);
      assert.equal(signals.cvss.version, version);
      assert.equal(signals.cvss.subject, A);
      assert.equal(signals.cvss.level, scoreLevel(score));
    });
});

test('numbers that are not scores are not read as scores', async (t) => {
  for (const text of [
    `${A} is fixed in CVSS 4.0 terms only.`,
    `${A} affects version 9.8 of the product.`,
    `${A} affected 9.8 million users; CVSS scoring is pending.`,
    `${A} is described by a CVSS:3.1/AV:N/AC:L vector.`,
    `${A} has a CVSS score of 98%.`,
    `${A} has a CVSS score of 11.5.`,
    `${A}: score each vendor on a 10-point scale.`,
  ])
    await t.test(text, () => assert.equal(read(text)?.cvss, undefined));
});

test('a score is tied to the nearest identifier before it, as in roundups and lists', () => {
  const list = `Critical issues: ${B} (CVSS score: 9.3) - A memory overflow can crash it. (Configured as a gateway) ${A} (CVSS score: 8.5) - A privilege flaw lets users escalate.`;
  assert.equal(read(list)?.cvss?.score, 8.5);
  assert.equal(read(list, { identifiers: [B], names: [] })?.cvss?.score, 9.3);
  // The other identifier's score never raises this one.
  assert.equal(read(`${B} (CVSS score: 9.8) was patched; ${A} is also fixed.`)?.cvss, undefined);
  // Two identifiers then one score: only the nearest counts, conservatively.
  assert.equal(read(`Tracked as ${A} and ${B}, both received a 9.2 CVSS rating.`)?.cvss, undefined);
  assert.equal(read(`Tracked as ${B} and ${A}, both received a 9.2 CVSS rating.`)?.cvss?.score, 9.2);
});

test('group statements are not read; an article about one subject is', () => {
  assert.equal(
    read(`Five flaws were fixed: ${A}, ${B} and three more. It scores all five 9.2 out of 10 on CVSS 4.0.`)
      ?.cvss,
    undefined,
  );
  assert.equal(read(`${A} was disclosed. ${B} was too. The flaw has a CVSS score of 9.8.`)?.cvss, undefined);
  assert.equal(read(`${A} was disclosed. The flaw has a CVSS score of 9.8.`)?.cvss?.score, 9.8);
  // A sentence that cites another identifier is about that one.
  assert.equal(read(`${A} was disclosed. It resembles CVE-2025-9999 (CVSS score: 9.8).`)?.cvss, undefined);
  // Exploitation is never read from the article's subject alone.
  assert.equal(
    read(`${A} was disclosed. The flaw is actively exploited in the wild.`)?.exploitation,
    undefined,
  );
});

test('a ZDI advisory without a CVE: the score is about the product its title names', () => {
  const target = { identifiers: [], names: ['Grizzl-E Smart 40A'] };
  const zdi = (title) =>
    newsSignals(
      [
        {
          title,
          description:
            'This vulnerability allows network-adjacent attackers to bypass authentication. Authentication is not required to exploit this vulnerability. The ZDI has assigned a CVSS rating of 7.6.',
        },
      ],
      target,
    );
  const signals = zdi(
    'ZDI-26-1037: (0Day) United Chargers Grizzl-E Smart 40A Authentication Bypass Vulnerability',
  );
  assert.equal(signals.cvss.score, 7.6);
  assert.equal(signals.cvss.subject, 'Grizzl-E Smart 40A');
  assert.equal(zdi('ZDI-26-1038: (0Day) Another Charger Authentication Bypass Vulnerability'), undefined);
});

test('the highest stated score wins when sources disagree', () => {
  const signals = read(
    `${A} has a CVSS 3.1 score of 8.1 from the vendor. Researchers gave ${A} a CVSS 4.0 score of 9.2.`,
  );
  assert.equal(signals.cvss.score, 9.2);
});

test('names bind a statement only when the article cites no other identifier', () => {
  const target = { identifiers: [], names: ['Acme Gateway'] };
  assert.equal(
    read('Acme Gateway is affected by a flaw with a CVSS score of 9.4.', target)?.cvss?.score,
    9.4,
  );
  assert.equal(
    read('Acme Gateway is affected by a flaw with a CVSS score of 9.4.', target)?.cvss?.subject,
    'Acme Gateway',
  );
  assert.equal(read(`Acme Gateway is affected by ${B}, with a CVSS score of 9.4.`, target)?.cvss, undefined);
  assert.equal(read('A flaw with a CVSS score of 9.4 was fixed in another product.', target), undefined);
});

test('vendor word ratings', async (t) => {
  for (const [text, level, word] of [
    [`${A}: Apache Kudu out-of-bounds read.\nSeverity: moderate`, 'medium', 'moderate'],
    [`${A} affects the kernel. The vendor rated ${A} Important.`, 'high', 'important'],
    [`${A} is a flaw that Oracle rates High.`, 'high', 'high'],
    [`For ${A}, Severity: critical`, 'critical', 'critical'],
  ])
    await t.test(text, () => {
      const signals = read(text);
      assert.equal(signals?.rating?.level, level);
      assert.equal(signals.rating.word, word);
    });
  assert.equal(read(`${A}: each visitor is then rated "important" or "useless".`)?.rating, undefined);
  assert.equal(read(`${A} is a high-risk issue rated high-severity by nobody.`)?.rating, undefined);
});

test('reported exploitation in the forms articles use', async (t) => {
  for (const text of [
    `A critical flaw in Apache Roller has come under active exploitation in the wild, according to the vendor (ASF) The vulnerability, tracked as ${A}, could lead to code execution.`,
    `${A} is now being actively exploited in the wild against both products.`,
    `Rapid7 detected exploitation of ${A} against a customer.`,
    `Attackers are exploiting ${A} to deploy miners.`,
    `Researchers said the first exploitation attempts aimed at ${A} began on Monday.`,
    `CISA added ${A} to its Known Exploited Vulnerabilities (KEV) catalog on Friday.`,
    `Apache Roller RCE Flaw ${A} Under Active Attack`,
    `${A} was released on Monday. "We are seeing bad guys exploiting this issue right now," the maintainer said.`,
  ])
    await t.test(text, () => {
      const signals = read(text);
      assert.equal(signals?.exploitation?.subject, A);
      assert.equal(signalLevel(signals).level, 'critical');
    });
});

test('negated, hedged and hypothetical statements are not reports of exploitation', async (t) => {
  for (const text of [
    `There is no evidence that ${A} has been exploited in the wild.`,
    `The vendor is not aware of any attacks; ${A} has not been exploited.`,
    `Neither the vendor nor the researchers report that ${A} was used in attacks.`,
    `Talos has not observed in-the-wild exploitation of ${A}.`,
    `As of today, there are no reports confirming active exploitation of ${A}.`,
    `Nobody has shown ${A} exploited in the wild.`,
    `${A} could be exploited in attacks to take over servers.`,
    `${A} may be exploited remotely without authentication.`,
    `Threat actors are suspected to be exploiting ${A}.`,
    `An attacker without an account can exploit ${A}.`,
    `Successful exploitation of ${A} hinges on a legacy mode.`,
    `Six zero-days, including ${A}, were found in an hour.`,
    `Has ${A} been exploited in the wild?`,
  ])
    await t.test(text, () => assert.equal(read(text)?.exploitation, undefined));
  assert.equal(
    read(`There is no evidence that ${A} has been exploited in the wild.`)?.no_known_exploitation?.subject,
    A,
  );
});

test('exploitation of another identifier in the same article does not count', () => {
  const text = `${A} is new and unpatched. It differs from ${B}, an older flaw that was actively exploited in attacks last year.`;
  assert.equal(read(text)?.exploitation, undefined);
  assert.equal(read(text, { identifiers: [B], names: [] })?.exploitation?.subject, B);
});

test('a KEV listing still counts when the vendor says it knows of no attacks', () => {
  const signals = read(
    `CISA added ${A} to its Known Exploited Vulnerabilities catalog on Tuesday. The vendor said it is not aware of attacks exploiting ${A}.`,
  );
  assert.equal(signals.exploitation.subject, A);
  assert.equal(signals.no_known_exploitation.subject, A);
  assert.equal(signalLevel(signals).level, 'critical');
});

test('public exploit code is shown and raises nothing', () => {
  const signals = read(`Rapid7 published a proof-of-concept for ${A}.`);
  assert.equal(signals.public_exploit.subject, A);
  const { level, reasons } = signalLevel(signals);
  assert.equal(level, 'unknown');
  assert.match(reasons.join('\n'), /public exploit code/);
  assert.equal(read(`Is there a proof-of-concept (PoC) available for ${A}?`), undefined);
  assert.equal(read(`No public exploit for ${A} has been released.`), undefined);
});

test('signal levels and reasons', () => {
  const signals = read(`${A} (CVSS score: 7.5) is patched. Severity: critical`);
  const { level, reasons } = signalLevel(signals);
  assert.equal(level, 'critical');
  assert.equal(reasons.length, 2);
  assert.match(
    reasons[0],
    /An article states CVSS 7\.5 for CVE-2026-1001; no advisory severity is available yet\./,
  );
  assert.equal(scoreLevel(9), 'critical');
  assert.equal(scoreLevel(7), 'high');
  assert.equal(scoreLevel(4), 'medium');
  assert.equal(scoreLevel(0.1), 'low');
});

test('identifiers match in any spelling, and the reading is bounded', () => {
  assert.equal(read(`cve-2026-1001 (CVSS score: 9.8) is out.`)?.cvss?.subject, A);
  const ghsa = 'GHSA-abcd-2345-efgh';
  assert.equal(
    read(`${ghsa.toUpperCase()} (CVSS score: 7.0)`, { identifiers: [ghsa], names: [] })?.cvss?.score,
    7,
  );
  const long = `${'Filler sentence without anything. '.repeat(3000)}${A} (CVSS score: 9.8).`;
  assert.equal(read(long), undefined);
  assert.equal(read('', { identifiers: [], names: [] }), undefined);
});

// Review of 2026-11-19.
test('a denial counts only before the statement in its clause', async (t) => {
  const acme = { identifiers: [], names: ['Acme Gateway'] };
  for (const [text, target] of [
    ['Acme Gateway is under active exploitation and no patch is available yet.', acme],
    [`Attackers are actively exploiting ${A} without authentication.`, undefined],
    [`No fix exists, but attackers are exploiting ${A} now.`, undefined],
  ])
    await t.test(text, () => {
      const signals = read(text, target);
      assert.ok(signals?.exploitation, JSON.stringify(signals));
      assert.equal(signals.no_known_exploitation, undefined);
    });
});

test('a report is tied to the identifier in its own clause', () => {
  const both = (text) => [
    read(text)?.exploitation?.subject,
    read(text, { identifiers: [B], names: [] })?.exploitation?.subject,
  ];
  assert.deepEqual(
    both(`${B} in Zeta Portal was patched in March, but attackers are now exploiting ${A} in Acme Gateway.`),
    [A, undefined],
  );
  assert.deepEqual(both(`${B} was patched last year; CISA added ${A} to its KEV catalog.`), [A, undefined]);
  assert.deepEqual(
    both(
      `Google said a Chrome zero-day is being actively exploited, and Mozilla also patched ${A} in Firefox.`,
    ),
    [undefined, undefined],
  );
});

test('a name is tied only within its clause', () => {
  const text =
    'Attackers are actively exploiting a zero-day in Acme Gateway, while Zeta Portal 2.1 adds dark mode.';
  assert.equal(read(text, { identifiers: [], names: ['Zeta Portal'] }), undefined);
  assert.equal(read(text, { identifiers: [], names: ['Acme Gateway'] }).exploitation.subject, 'Acme Gateway');
  const score = 'Acme Gateway has a flaw with a CVSS score of 9.8, while Zeta Portal only adds dark mode.';
  assert.equal(read(score, { identifiers: [], names: ['Zeta Portal'] })?.cvss, undefined);
  assert.equal(read(score, { identifiers: [], names: ['Acme Gateway'] }).cvss.score, 9.8);
});

test('counts, versions and thresholds next to CVSS are not scores', async (t) => {
  const windows = { identifiers: [], names: ['Windows'] };
  for (const text of [
    'Microsoft fixed 10 CVSS critical flaws in Windows.',
    'Windows now uses CVSS v4 metrics.',
    'Windows advisories carry a CVSSv3 vector.',
    'For Windows, a CVSS score of 7 or higher must be patched within a week.',
    'Windows flaws rated CVSS 9.0+ are patched first.',
    'Windows flaws above a CVSS score of 8.0 are patched first.',
  ])
    await t.test(text, () => assert.equal(read(text, windows)?.cvss, undefined));
  assert.equal(read('Windows has a flaw with a CVSS score of 10.', windows).cvss.score, 10);
  assert.equal(read('Windows: CVSS 3.1: 5.5 MEDIUM', windows).cvss.score, 5.5);
});
