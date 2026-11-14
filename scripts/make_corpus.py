"""Generate the synthetic evaluation corpus into data/corpus/. NOT IMPLEMENTED YET.

Plan (proposal section 5):
  * 200 benign (incl. 40 real-looking security notices), 100 plain phishing,
    100 phishing with hidden instructions (60 tuning / 40 held-out, Diva only)
  * Korean / English 50:50, template-based, fake names and `.test` domains
  * 20 secret marker strings planted in other mails for the exfiltration test
  * also 50 correct cases re-run with a confident false claim (sycophancy test)
Every file name encodes its ground-truth label so the eval script never guesses.
"""
raise SystemExit("make_corpus.py is a placeholder; see the docstring for the plan")
