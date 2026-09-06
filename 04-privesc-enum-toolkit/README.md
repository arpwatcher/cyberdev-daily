# privesc-enum-toolkit

Linux privilege escalation enumeration, the kind of checks you'd run by hand on a
tryhackme box or during an actual pentest, built into a small tool instead of copy-pasting
one-liners. Ties into the LPIC-1 system knowledge from `01-lpic1-sysadmin-toolkit` - same
territory, different angle (finding what's wrong instead of just inspecting).

- `suid.py` - walks a directory tree for setuid/setgid binaries and flags anything outside
  a common baseline (passwd, sudo, su and the like are expected; something in /tmp with
  the suid bit set is not)
- `sudo_perms.py` - parses `sudo -l` output and flags the blanket `ALL` permission plus
  any binary with a well known gtfobins-style sudo shell escape (vim, find, python, awk,
  and a dozen others that show up constantly on ctf boxes)
- `cron.py` - parses crontab entries (both `/etc/crontab` style with a user field and
  `crontab -l` style without) and flags jobs that run a world-writable script, or a script
  sitting in a world-writable directory - if you can edit what root's cron job runs, you
  get root the next time it fires
- `path_check.py` - checks `$PATH` for directory-order hijacking: if a writable directory
  comes before the real location of a binary, an attacker can drop a malicious file with
  that name and have it run instead of the real one
- `capabilities.py` - parses `getcap -r /` output and flags binaries with a capability
  that amounts to privilege escalation (cap_setuid lets a binary change its own uid
  outright, which a plain suid/sgid scan won't catch since there's no suid bit involved)

## Usage

```
cd 04-privesc-enum-toolkit
python -m privesc.cli suid /
python -m privesc.cli sudo sudo_l_output.txt
python -m privesc.cli cron /etc/crontab
python -m privesc.cli cron ~/mycrontab --user-format
python -m privesc.cli path --binaries sudo,python3,bash
python -m privesc.cli caps getcap_output.txt
```

## Tests

```
pip install pytest
pytest
```

35 tests. The suid, cron and path checks run against real files with real permission
bits set in a temp directory (not mocked stat results), so they're exercising the actual
filesystem checks, not just the parsing logic. The capabilities parser caught a real bug
during development - getcap output uses either `=` or `+` before the eip flags depending
on version, and the first pass only handled one of them.
