# Synthetic case corpus

300 synthetic `.eml` files generated from templates (`scripts/make_corpus.py`),
Korean/English 50:50, fake domains, 20 secret marker strings planted in bodies
for the exfiltration test. Indexed into `workspace.sqlite3` (sender, recipient,
time, path only) so `search_sender` can run against it.

Not generated yet. Owner: shared; the 40 held-out injection mails will be distributed again.
