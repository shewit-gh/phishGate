"""PhishGate: a phishing-triage agent the e-mail cannot steer.

Package layout mirrors Figure 1 of the proposal:

    intake/      UNTRUSTED ZONE  .eml upload, fingerprint, prompt assembly   (S1, Shewit)
    rules/       UNTRUSTED ZONE  read-only header / URL / attachment rules   (S1, Shewit)
    agents/      both zones      analysis agent + action agent + LLM client
    schemas/     seam contracts  Verdict, Facts, CheckedVerdict, ActionProposal
    verifier/    CONTROL ZONE    code that recomputes facts, sets HOLD        (S2, Diva)
    gate/        CONTROL ZONE    policy limits, the only caller of tools      (S3, Junhee)
    tools/       CONTROL ZONE    notify / search_sender / quarantine          (S3, Junhee)
    workspace/   data stores     sqlite case corpus, queue, quarantine
    audit/       cross-cutting   hash-chained audit log + abuse monitor       (Diva)
"""

__version__ = "0.1.0-skeleton"
