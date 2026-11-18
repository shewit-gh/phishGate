# Verdict labels and case states

Source of truth is `phishgate/schemas/verdict.py` (seam S2). This file mirrors its
docstrings so the prompt (S1), the verifier (layer 3) and the corpus labels use one
meaning. If the two disagree, the code wins and this file gets fixed.

## Indicators

An **indicator** is any reason code other than `none`.

| code | meaning | kind |
|---|---|---|
| `sender_auth_fail` | SPF, DKIM or DMARC failed in `Authentication-Results` | hard |
| `suspicious_link` | IP-literal or punycode URL, or link text that does not match its target | hard |
| `dangerous_attachment` | executable, macro document, or declared type that does not match the bytes | hard |
| `mismatched_reply_to` | `Reply-To` domain differs from the `From` domain | soft |
| `lookalike_domain` | sender domain imitates a known brand or the recipient's own domain | soft |
| `urgent_language` | pressure to act now (deadline, account closure, threat) | content |
| `credential_request` | asks for a password, login, one-time code or similar | content |
| `payment_request` | asks for a payment, bank-detail change, gift card or invoice settlement | content |

Hard and soft indicators are recomputed by plain code from the `.eml`. Hard ones are
compared with the model's claims; soft ones only stop a `benign` label. Content
indicators come from the model alone.

## Labels (what the model may choose)

| label | definition |
|---|---|
| `benign` | No indicator is present. Nothing for the analyst to do; the case is closed. |
| `suspicious` | At least one indicator is present but the phishing rule is not met. An analyst must look; no action is proposed. |
| `phishing` | A credible attempt to obtain credentials, money or data, or to deliver malware. |

**Phishing rule.** A mail is `phishing` when any one of these holds:

- (a) `sender_auth_fail` and (`credential_request` or `payment_request`)
- (b) `lookalike_domain` and (`credential_request` or `payment_request`)
- (c) `dangerous_attachment`
- (d) `suspicious_link` and `credential_request`

Otherwise, one or more indicators means `suspicious`; none means `benign`.

## Case states (set by the verifier, never by a model)

| status | when |
|---|---|
| `closed` | label `benign`, every claim agrees with the facts, no indicator, confidence at or above 0.6. |
| `to_analyst` | label `suspicious` or `phishing` and the claims agree with the facts. An analyst reviews; the action agent may propose actions. |
| `hold` | a claim contradicts the recomputed facts, or the label is `benign` with any indicator or confidence under 0.6, or the model gave no valid output. The case stops: no action agent, no tool call. `hold_reason` says why. |

`HOLD` is not a label. The model cannot choose it, and nothing in an e-mail can
cause or prevent it; only the comparison between claims and recomputed facts does.

## Who uses this

- **S1 prompt** (`phishgate/intake/prompt_assembly.py`): the label table is given to the model word for word.
- **Verifier** (`phishgate/verifier/verifier.py`): applies the state rules.
- **Corpus** (`scripts/make_corpus.py`, `data/corpus/`): every generated mail is labelled by the phishing rule.