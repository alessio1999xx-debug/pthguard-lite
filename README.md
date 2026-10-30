# pthguard-lite: find malicious .pth files in Python site-packages

Python runs every line that starts with `import` in a .pth file inside site-packages each time the interpreter starts, which makes these files a quiet place for a supply-chain backdoor. pthguard-lite helps you list the .pth files in an environment and flag the lines that execute code, using only the standard library.

- One file, Python 3.8+. Nothing to `pip install`.
- Safe to invoke as `python -I -S` so your own site customizations stay off.
- Plain text report; exit code `1` when a HIGH or CRITICAL finding appears.

## Install

```bash
curl -fsSLO https://raw.githubusercontent.com/alessio1999xx-debug/pthguard-lite/main/pthguard_lite.py
chmod +x pthguard_lite.py
python -I -S pthguard_lite.py --help
```

## What a malicious .pth file looks like

Most `.pth` lines are plain path entries. Only lines that start with `import` (or `import` + a tab) are executed by Python's `site` module. A dangerous line looks like this harmless demo — do not put this in a real environment:

```text
# path entry (not executed)
/opt/extra/libs
# executed at every interpreter start:
import os; os.system("echo demo-only")
```

pthguard-lite opens `.pth` files as text, skips known-benign virtualenv/setuptools hooks, and flags lines that use patterns such as `exec`, `eval`, `base64`, `subprocess`, `os.system`, `__import__` or a network call. It also checks `sitecustomize.py` and `usercustomize.py` for the same class of startup persistence. It never imports or runs code from the target tree.

## Scan site-packages for backdoors locally and in CI

```bash
# one venv / site-packages tree
python -I -S pthguard_lite.py /path/to/venv/lib/python3.12/site-packages

# or a single .pth / sitecustomize.py file
python -I -S pthguard_lite.py ./suspicious.pth
```

Minimal GitHub Actions step (fails the job when HIGH/CRITICAL findings appear):

```yaml
- name: Scan site-packages with pthguard-lite
  run: >
    python -I -S pthguard_lite.py
    "$(python -c 'import site; print(site.getsitepackages()[0])')"
```

| Finding | What it means |
|---|---|
| `MALICIOUS_PTH_HOOK` | An executable `.pth` line matches a high-risk pattern |
| `EXECUTABLE_PTH_LINE` | An `import …` line runs at startup but is not a known-benign hook — review it |
| `SUSPICIOUS_CUSTOMIZE_HOOK` | `sitecustomize.py` / `usercustomize.py` looks like credential harvest, decode, subprocess or sockets |

## pthguard-lite vs PthGuard

pthguard-lite checks **one** path for risky startup hooks and prints a text report. It does not verify package integrity or scan a whole fleet.

The full **[PthGuard Python backdoor scanner](https://py-forge.com/products/pthguard-python-backdoor-scanner?utm_source=github&utm_medium=readme&utm_campaign=pthguard-lite)** adds:

- dist-info `RECORD` SHA-256 verification and unrecorded-file listing
- offline known-bad package list (extendable JSON)
- IOC / persistence path checks
- many venvs, conda prefixes or a Docker rootfs in one run
- JSON report, stricter CI exit codes, and a quarantine script you review before running

One-time payment, yours to keep. No subscription.

Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=pthguard-lite).

## Tests

```bash
python3 test_pthguard_lite.py
```

## License

MIT (this lite version). The full PthGuard tool is sold separately under its own license.
