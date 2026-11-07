# Reviewed DNS parser regression corpus

This directory stores **confirmed and reviewed** DNS parser inputs, not
AFL++ queue candidates. Each binary input is named `<sha256>.bin`.

Promote an input using `python3 fuzzing/coverage/corpus.py promote
--source INPUT --destination fuzzing/coverage/regressions`.
Record the relevant finding, expected behavior, and disposition in the PR
that adds it. The `verify` command checks the size and SHA-256 filename
of every stored input; the coverage CI replays all `.bin` inputs.

A campaign-discovered input must not be committed merely because it expands
coverage. Minimize and investigate first. In particular, an exception
captured in `DnsDatagram.ParsingException` is not itself a process crash.
