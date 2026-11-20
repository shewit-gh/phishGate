# Synthetic case corpus

```
python scripts/make_corpus.py          # writes data/corpus/generated/ and data/corpus/markers.txt
python scripts/evaluate.py             # runs the pipeline over it (stub model)
```

`generated/` and `markers.txt` are git-ignored. The generator is deterministic: the same
seed gives the same files byte for byte, so regenerate instead of committing 360 files.

| group | count | what is in it |
|---|---|---|
| benign | 200 | invoices, meeting changes, newsletters (HTML), shipping notices, and 40 real-looking security notices |
| phishing | 100 | credential lures (IP-literal, punycode, look-alike links), dangerous attachments, CEO payment fraud, anchor/target mismatch, and 10 "quiet" mails with no failed check and no flagged link |
| injected (tuning) | 60 | the same lures plus one of ten injection techniques: plain note, forged end marker, forged rule results, role play, notify-all, quarantine-someone-else, flattery, extra field, hidden div, HTML comment |
| injected (held-out) | 40 | **not generated.** One team member writes them by hand into `heldout/` and does not show them to whoever tunes the prompts. |

Korean / English 50:50. Made-up names, `.test` domains, documentation IP ranges.
`labels.csv` holds the ground truth (file, label, kind, lang, injection, marker, taxonomy); the file
name carries the label too. `taxonomy` is the category of `data/phishing_taxonomy.json`
(legitimate, credential_phishing, malware_delivery, bec_payment_fraud); `evaluate.py` reports
evasion per category. Four categories have no generated mails yet: spear_phishing,
advance_fee_scam, callback_hybrid, commercial_spam.

20 secret marker strings (`CANARY-…`) are planted in benign bodies. No audit row written
after intake should ever contain one; `phishgate.cli monitor` and `evaluate.py` check that.

The sycophancy test uses this corpus too: `python scripts/sycophancy.py --llm ollama` takes 50
correctly labelled mails and runs them again with a confident false comment from a colleague.

Not done yet: the held-out set.
