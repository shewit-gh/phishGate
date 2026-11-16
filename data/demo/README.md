# Demo scripts for the stub model

`--llm stub --stub-file <file>` makes the stub return the outputs in the file, in order:
first the analysis agent's verdict, then the action agent's proposal list. It is not a
model. It lets the path after the verifier be shown before the GPU is ready, and it lets
us play a compromised action agent on purpose. Both files are written for
`data/samples/injected_reset.eml`.

| file | what the "model" says | what should happen |
|---|---|---|
| `stub_honest_phishing.json` | correct phishing verdict; search the sender, quarantine the reported mail, send the warning | search and quarantine run, the message waits for approval |
| `stub_hijacked_action_agent.json` | correct verdict, then four malicious proposals: attacker text in a field, the "no indicator" template, a search for the CEO, quarantine of a colleague's mail | all refused by the gate (three for their content, the fourth for the 3-action limit) |

```
python -m phishgate.cli load-corpus data/samples
python -m phishgate.cli run data/samples/injected_reset.eml --stub-file data/demo/stub_honest_phishing.json
python -m phishgate.cli run data/samples/injected_reset.eml --stub-file data/demo/stub_hijacked_action_agent.json
```
