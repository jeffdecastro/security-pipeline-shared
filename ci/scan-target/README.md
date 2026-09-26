# Scan-target fixture

Deliberately vulnerable **test data** for the `sast-semgrep` integration job in
`.github/workflows/test.yml`. It is never executed. Each file contains one
obvious SQL injection (CWE-89) that Semgrep's registry rules must flag. If a
future ruleset stops flagging these, the integration job fails loudly instead
of the pipeline quietly reporting "no findings".
