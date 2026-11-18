# PhishGate: a phishing-triage agent the e-mail cannot steer

Secure AI Systems, Korea University, 2026-2. Team Ctrl3, Track B (secured agent).

The analyst uploads one reported `.eml`. An open-weight model reads it and writes a
fixed-format verdict. Plain code re-checks the verdict against facts it computes
itself, and anything that contradicts the facts stops as HOLD. A second copy of the
model, which never sees the e-mail, proposes actions; a gate with fixed limits is the
only thing that can run a tool; every message waits for a human click. Everything
stays inside a local case workspace: no mailbox, no mail server, no network.

![architecture](docs/Figure1_PhishGate_architecture.png)

## Status: every box of Figure 1 runs with a stub model; the real model is not connected yet

What runs today, with a stub model and no GPU:

```
python -m phishgate.cli load-corpus data/samples                 # index the eleven sample mails
python -m phishgate.cli run data/samples/benign_invoice.eml      # -> closed
python -m phishgate.cli run data/samples/injected_reset.eml      # stub obeys the injection -> verifier says HOLD
python -m phishgate.cli run data/samples/injected_reset.eml --stub-file data/demo/stub_honest_phishing.json
                                                                 # search + quarantine run, the message waits for approval
python -m phishgate.cli run data/samples/injected_reset.eml --stub-file data/demo/stub_hijacked_action_agent.json
                                                                 # a hijacked action agent: the gate refuses everything
python -m phishgate.cli queue                                    # what is waiting for the analyst
python -m phishgate.cli audit --verify                           # hash chain check
python -m phishgate.cli monitor                                  # alerts
python -m phishgate.cli serve                                    # the analyst page, http://127.0.0.1:5000
python scripts/make_corpus.py && python scripts/evaluate.py      # 360-mail corpus and the section-5 numbers
python scripts/sycophancy.py                                     # plumbing only with the stub; needs the model
python -m pytest -q                                              # 89 passed, 1 skipped (needs the model)
```

Not done: the real model (Qwen on the lab GPU), `bom.yaml` hashes, the 40 held-out injection
mails. The sycophancy script and datamarking are written but have never met a real model.

Latest changes and open questions: [docs/CHANGES_2026-11-16.md](docs/CHANGES_2026-11-16.md).

With Ollama running Qwen locally: `--llm ollama --model qwen2.5:14b`.

## Layout: one folder per box in Figure 1

| folder | zone | what it is |
| --- | --- | --- |
| `phishgate/intake/` | untrusted | `.eml` upload, SHA-256, spotlighted prompt assembly |
| `phishgate/rules/` | untrusted (and re-run in control) | read-only header / URL / attachment rules |
| `phishgate/agents/` | both | analysis agent, action agent, local LLM client + stub |
| `phishgate/schemas/` | boundary | **the contracts**: `Verdict`, `Facts`, `CheckedVerdict`, `ActionProposal` |
| `phishgate/verifier/` | control | plain code; recomputes facts; HOLD on contradiction |
| `phishgate/gate/` | control | policy limits; the only caller of tools |
| `phishgate/tools/` | control | `notify`, `search_sender`, `quarantine` / `release` |
| `phishgate/workspace/` | data | sqlite corpus index, quarantine flags, analyst queue, `outbox/` |
| `phishgate/audit/` | cross-cutting | hash-chained audit log, abuse monitor |
| `phishgate/pipeline.py` | orchestrator | the seven steps in order; the only place S1, S2, S3 meet |
| `data/samples/` |  | ten hand-written synthetic mails for the demo |
| `data/templates/` |  | the fixed notify templates and their allow-listed fields |
| `data/corpus/` |  | synthetic evaluation corpus (to generate) |
| `tests/` |  | one seam test per seam, plus the audit-chain test |
| `phishgate/web.py` | control | the analyst page (Flask, local only) |
| `data/demo/` |  | canned model outputs for the stub, for demos without a GPU |
| `scripts/` |  | corpus generator, evaluation, BOM check |

Trust boundary 1 is the call from `pipeline.py` into `verifier.verify()`: only a
`Verdict` crosses, never e-mail text. Trust boundary 2 is `Gate.run()`: only the gate
imports `tools/`.

## Every file and what it does

### Top level

| file | what it is |
| --- | --- |
| `README.md` | this file. Setup, layout, working agreement, roadmap. |
| `requirements.txt` | Python dependencies, exact versions. |
| `requirements.lock` | the same set with all transitive dependencies and SHA-256 hashes, for `pip install --require-hashes`. Written by `scripts/lock_requirements.py`. |
| `bom.yaml` | ML bill of materials (proposal section 3): model source, revision, file hashes, intake checks. Placeholders until the weights are downloaded. |
| `.gitignore` | keeps `.venv/`, `workspace/`, `*.sqlite3` and model weights out of git. |
| `docs/Figure1_PhishGate_architecture.png` | the architecture figure from the proposal. |

### `phishgate/` : the system (one sub-package per box in Figure 1)

| file | zone | what it does |
| --- | --- | --- |
| `__init__.py` |  | package docstring with the layout map and version. |
| `pipeline.py` | orchestrator | `PhishGate.run_case()`: the seven steps in order (intake, analysis agent, verifier, action agent, gate, tools, queue). Writes every step to the audit log. A HOLD case is put in the analyst queue; a model that never returns a valid verdict fails closed as HOLD. The only place where S1, S2 and S3 meet. |
| `cli.py` | analyst stand-in | `run` one .eml, `load-corpus`, `queue`, `approve`, `reject`, `quarantined`, `release`, `audit --verify`, `monitor`, `serve`. `--stub-file` scripts the stub model. |
| `web.py` | analyst page | Step 7 as a web page: upload a reported `.eml`, approve / reject the queue, release a quarantine, see alerts and the audit log. Binds to 127.0.0.1, no JavaScript, strict CSP, a form token on every POST, all values escaped. |

#### `phishgate/intake/` : untrusted zone, step 1 and 2a

| file | what it does |
| --- | --- |
| `intake.py` | `ingest()`: read the upload, refuse over 2 MB, SHA-256 fingerprint, store a byte-identical copy in `workspace/cases/<id>/original.eml`, parse with the standard library. Returns a `Case`. |
| `prompt_assembly.py` | `build_analysis_prompt()`: spotlighting (defence layer 2). Fixed instructions first, then the e-mail inside a data block fenced by a per-run random nonce, headers / body / attachments labelled by origin, nonce stripped from the mail so it cannot forge a boundary. An HTML body is reduced to the text a reader sees (hidden elements and comments dropped); a mail with a plain and an HTML part shows both. Datamarking: every space in the body, the subject and attachment names becomes the marker `ˆ`, and the prompt says outside the block that such text is never an instruction (`PHISHGATE_DATAMARK=0` switches it off for comparison). An optional analyst comment, used only by the sycophancy test, goes after the block and is labelled as opinion. |

#### `phishgate/rules/` : read-only tools (look, don't act)

Used twice: as the analysis agent's tool results and, re-run independently, as the verifier's facts.

| file | what it does |
| --- | --- |
| `header_rules.py` | `check_headers()`: SPF / DKIM / DMARC result from the Authentication-Results header (`softfail` counts as a failure unless DMARC passed), From domain and address, Message-ID, Reply-To on another registrable domain, look-alike sender domain. Address and id are passed on only if they have a plain shape. No network, so no live DMARC lookup (accepted gap). |
| `url_rules.py` | `check_urls()`: every link in text and HTML parts, hidden ones included; flags IP-literal hosts, punycode, look-alike domains, and anchor text that shows a different domain than its target. Also reports whether the HTML holds hidden text or comments. |
| `domains.py` | `registrable()` and `is_lookalike()`: a host that imitates a domain listed in `data/org_domains.txt` (organisation name as a word, confusable characters, one-letter typo). |
| `html_text.py` | `html_view()`: HTML to visible text with the standard library; drops comments, scripts and CSS-hidden elements and reports that they were there. |
| `attachment_rules.py` | `check_attachments()`: dangerous extension, plus the content itself: bytes that start like a program, shortcut or disk image whatever the name says; an Office file (new or old format) that carries a VBA project; a ZIP with a dangerous member. Standard library only; nothing is unpacked or run. It says a macro is present, not what it does. An encrypted archive is reported but not called dangerous. |
| `facts.py` | `rule_summary()` (loose dict for the prompt) and `compute_facts()` (typed `Facts` for the verifier) from the three modules above. |

#### `phishgate/schemas/` : the seam contracts

| file | what it does |
| --- | --- |
| `verdict.py` | What crosses trust boundary 1. `Label` (benign / suspicious / phishing), `ReasonCode` (closed list), `Verdict` (exact fields, extra fields rejected, no free text), `Facts` (recomputed by code: the three hard facts, the soft indicators `reply_to_mismatch` and `lookalike_sender`, and the sender address and message id the action agent may act on), `CaseStatus` (closed / to_analyst / hold), `CheckedVerdict` (verdict + facts + status, no e-mail text). |
| `proposal.py` | What the action agent may propose. `QuarantineArgs`, `SearchSenderArgs`, `NotifyArgs` (template id + fields only), union `ActionProposal`. |

#### `phishgate/agents/` : the one model, used twice

| file | what it does |
| --- | --- |
| `llm_client.py` | `LLMClient` protocol. `OllamaClient` talks to a local Ollama server (JSON mode, temperature 0). `StubLLM` returns canned JSON and records every prompt, so everything runs without a GPU. |
| `analysis_agent.py` | Step 2. Builds the prompt, calls the model at most 3 times until the output is a valid `Verdict`. Has no action tools. |
| `action_agent.py` | Step 4. Receives only the `CheckedVerdict` as JSON, never the e-mail. The prompt tells it which values to use and which template fits which label. Returns typed proposals; unparsable output becomes an empty list. |

#### `phishgate/verifier/` : control zone, step 3 (defence layer 3)

| file | what it does |
| --- | --- |
| `verifier.py` | `verify()`: plain code. Recomputes `Facts` from the stored original, compares them with the model's three claims; any contradiction, or a benign label with a hard indicator, a soft indicator (Reply-To elsewhere, look-alike sender) or confidence under 0.6, becomes HOLD with the reason written by code. Benign and consistent closes; suspicious / phishing goes to the analyst. |

#### `phishgate/gate/` : control zone, step 5 (defence layer 4)

| file | what it does |
| --- | --- |
| `policy.py` | `Policy`: the fixed limits from the proposal (12 tool calls per case, 3 actions per round, 10 messages per hour, bulk quarantine over 5 needs a human, the allowed template names, and which template fits which verdict label). |
| `gate.py` | `Gate.run()`: the only caller of tools (trust boundary 2). Refuses everything unless the case is `to_analyst`, refuses the fourth action and the thirteenth tool call of a case, refuses a notify whose template is not allow-listed or does not match the label, whose field names are not allow-listed, or whose field values differ from what the gate derives itself (the model's values never reach a message). Refuses a quarantine that names an id not in the corpus or a mail from anyone but the sender of this case, and a `search_sender` for any other address. Queues every message and every bulk quarantine for a human, executes small quarantines and sender searches. Every refusal is logged with its reason. |

#### `phishgate/tools/` : step 6, imported by the gate only

| file | what it does |
| --- | --- |
| `notify.py` | `draft()`: fills a template from `data/templates/` by replacing only its declared placeholders (a missing field becomes blank, never model text) and puts the draft in the analyst queue. Nothing is sent. |
| `search_sender.py` | `search()`: other mails from the same sender; returns sender, recipient, time only. No subject, no body. |
| `quarantine.py` | `quarantine()` / `release()` set or clear a flag on messages and move the working copy between `workspace/corpus/` and `workspace/quarantine/` (reversible). `queue_bulk()` sends large requests to the approval queue. |

#### `phishgate/workspace/` : the local case workspace (data stores)

| file | what it does |
| --- | --- |
| `db.py` | `Workspace`: one SQLite file. Table `corpus` = metadata index of the synthetic mails with a quarantine flag. Table `queue` = pending message drafts, bulk approvals and HOLD cases. `decide()` is the analyst's click: an approved message becomes a file in `workspace/outbox/`. |
| `corpus.py` | `load_corpus()`: index a folder of `.eml` files (sender, recipient, time only) and keep a working copy of each under `workspace/corpus/`, named by a hash of the message id. |

#### `phishgate/audit/` : audit log and abuse monitor (defence layer 6)

| file | what it does |
| --- | --- |
| `audit_log.py` | `AuditLog`: append-only SQLite rows, each carrying the SHA-256 of the previous row. `verify_chain()` recomputes every hash from the genesis value; editing one row breaks the chain there. |
| `monitor.py` | `AbuseMonitor`: reads the log after the fact. `alerts()` with thresholds: HOLD rate, refusals per case, limit overruns, message volume, model output that never parsed, a domain closed as benign after it was flagged, and canary markers found in any row written after intake. |

### `data/`

| path | what it is |
| --- | --- |
| `samples/*.eml` | ten synthetic mails: four benign, three phishing, three with injected instructions; Korean and English. |
| `demo/*.json` | canned outputs for `--stub-file`: an honest run and a hijacked action agent. |
| `org_domains.txt` | the organisation's own domains, used by the look-alike rule. |
| `samples/README.md` | one row per mail: what it is, the recomputed facts, the stub result and the target result. |
| `templates/*.json` | the three notify templates (`phishing_warning`, `hold_notice`, `benign_closed`): subject, body, and the only fields the gate accepts. |
| `corpus/README.md` | plan for the 300-mail synthetic corpus. Not generated yet. The 40 held-out injection mails go in a separate folder nobody on S1 reads. |

### `tests/`

| file | what it checks |
| --- | --- |
| `conftest.py` | fixtures that load two of the sample mails. |
| `test_seam_s1.py` | injected text sits inside the data block, after the instructions. A forged end marker does not close the block. The real-model test (fake verdict in body not echoed) runs when `PHISHGATE_OLLAMA_MODEL` is set. |
| `test_seam_s2.py` | the injected benign verdict becomes HOLD; a consistent benign verdict closes; an honest phishing verdict goes to the analyst; an extra field is rejected by the schema. |
| `test_seam_s3.py` | a fourth action is refused and logged; a notify field not on the allow-list is refused; notify only ever queues; a HOLD or CLOSED case allows no action; attacker text in a field value is refused; a template that does not match the label is refused; the 12-call budget holds across rounds; unknown quarantine ids are refused. |
| `test_pipeline.py` | whole pipeline with the stub: a HOLD case reaches the analyst queue; invalid model output fails closed; an honest phishing case ends in a queued message with no e-mail text. |
| `test_workspace.py` | corpus loader, quarantine and release as a file move, the `load-corpus` / `release` commands. |
| `test_rules.py` | look-alike domains, softfail, Reply-To, anchor/target mismatch, hidden HTML never reaches the prompt, the verifier's soft indicators and confidence floor, attachment content checks. |
| `test_monitor.py` | each alert, and that a canary marker in an outgoing row is found without being repeated. |
| `test_web.py` | the analyst page: security headers, POST without the token refused, upload to HOLD to review, approve into `outbox/`, attacker text escaped. |
| `test_scripts.py` | BOM check passes then fails on any change and fails closed when unfilled; the corpus is reproducible; the evaluation runs; the sycophancy script counts flips and what the verifier still stops. |
| `test_audit_chain.py` | the chain verifies, and breaks at the edited row after tampering. |

### `scripts/`

| file | what it does |
| --- | --- |
| `make_corpus.py` | generates the synthetic evaluation corpus into `data/corpus/generated/` (git-ignored; same seed, same bytes): 200 benign (40 real-looking security notices), 100 phishing, 60 injected with ten injection techniques, Korean / English 50:50, 20 canary markers in `data/corpus/markers.txt`, ground truth in `labels.csv`. The 40 held-out injection mails are written by hand, not here. |
| `evaluate.py` | runs the pipeline over a labelled corpus and prints the numbers of proposal section 5: model precision / recall, evasion rate, HOLD rate on benign, refusals, traced cases, canary hits. `--llm stub` gives the floor (a model that obeys every injection); `--llm ollama` gives the real numbers. |
| `sycophancy.py` | takes 50 mails the model labels correctly, runs them again with a confident false comment from a colleague, and counts how often the label changes sides and whether the verifier still stops the case. Meaningful with `--llm ollama` only. |
| `lock_requirements.py` | writes `requirements.lock` from the installed environment and PyPI's published hashes. |
| `check_bom.py` | verifies `models/<name>/` against `bom.yaml` before the model server starts: commit hash present, every file listed with a matching SHA-256, nothing unlisted, no pickle-format file, no `auto_map` in `config.json`. Fails closed (the unfilled BOM is an error). `--record` prints the `files:` block to paste. |

### Generated at run time (git-ignored)

| path | what it is |
| --- | --- |
| `workspace/cases/<case_id>/original.eml` | stored copy of each upload. |
| `workspace/workspace.sqlite3` | corpus index, quarantine flags, analyst queue. |
| `workspace/corpus/`, `workspace/quarantine/` | working copies of the loaded mails; quarantine moves a file from the first to the second. |
| `workspace/audit.sqlite3` | the hash-chained audit log. |
| `workspace/outbox/` | approved messages as text files. Never sent. |

## Working agreement

* Anyone may work on any part. Changes to `phishgate/schemas/` are still announced to everyone
  first, because every seam depends on them.
* Every pull request keeps `python -m pytest -q` green.
* `workspace/` and `*.sqlite3` are generated and git-ignored. Model weights never go in the repo.
* Synthetic data only. Made-up names, `.test` domains. No real mail.

## Setup

```
python -m venv .venv
.venv\Scripts\activate            # Windows   (source .venv/bin/activate on Linux)
pip install --require-hashes -r requirements.lock      # or: pip install -r requirements.txt
python -m pytest -q
```

## Roadmap to the mid-check (Mon 23 Nov 2026)

1. Confirm the model and serving stack on the lab GPU; download the weights, run
   `python scripts/check_bom.py --record <name>`, paste the result and the commit hash into `bom.yaml`.
2. Run `PHISHGATE_OLLAMA_MODEL=... python -m pytest -q`, `python scripts/evaluate.py --llm ollama`
   (once more with `PHISHGATE_DATAMARK=0` to see what datamarking costs or buys) and
   `python scripts/sycophancy.py --llm ollama`; tune the two prompts on the tuning set only.
3. Write the 40 held-out injection mails by hand (`data/corpus/heldout/`).
4. Video: problem (30 s), diagram with repo tree (90 s), live run of a benign then an injected
   mail ending in HOLD and the audit line (2 min), what is not built yet and the number
   we will report (1 min).

## AI use

Skeleton structure drafted with Claude (Anthropic, Fable 5.1) from the team's proposal;
design decisions, limits and ownership are the team's. Keep this section updated.

The changes of 16 Nov 2026 (branch `JH-261116`, listed in `docs/CHANGES_2026-11-16.md`) were written
with Claude Code (Anthropic, Fable 5.2) under Junhee's direction: gate hardening, pipeline fail-closed
paths, corpus loader, rules, monitor, analyst page, scripts, sample mails and tests. The team reviews
them before they are merged.
