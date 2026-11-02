# File Integrity Checker

An offline cybersecurity tool that compares SHA-256 file fingerprints to a trusted baseline and reports **added, modified and deleted files**. Python 3.10+, standard library only, no installation or internet connection needed.

## Try it

From this repository folder, run:

```bash
python integrity.py baseline examples/watched --baseline baseline.json
python integrity.py check examples/watched --baseline baseline.json
```

On Windows, use `py` in place of `python` if necessary. Open `examples/watched/settings.txt`, change a value, save it, then run the second command again. The JSON report will list `settings.txt` under `modified`. Creating or deleting a file in that folder also appears in the report.

Example after changing the settings file:

```json
{
  "added": [],
  "deleted": [],
  "modified": ["settings.txt"],
  "unchanged": 0,
  "skipped": []
}
```

## How it works

The baseline command saves each regular file's relative path and SHA-256 hash. The check command hashes the current folder and compares the results. Files are read in chunks; nested folders, empty files and binary data are supported. Symbolic links and special files are skipped and listed. Read errors abort the scan instead of reporting inaccessible files as deleted.

Exit codes: **0** baseline created or no content changes; **1** differences found; **2** input or scanning error. Skipped entries are informational and must be reviewed even when the exit code is 0.

## Baseline handling

Keep the baseline **outside** the monitored folder. Existing baselines are never overwritten. After reviewing legitimate changes, save a new baseline under a different filename. Keep a protected copy; anyone who can alter both the monitored files and the baseline can hide changes. Baselines contain file names and hashes, not file contents. Do not publish baselines for sensitive folders.

## Scope and limits

This detects content changes, not malware or intent. It does not monitor continuously, restore files, or compare permissions, timestamps, ownership, empty directories or link targets. Renames appear as deletion plus addition. The baseline does not bind to an absolute folder, so you can compare copies of the same folder. Stop writes while scanning: scans are not atomic snapshots, and this is not designed for directories actively manipulated by an adversary. Basic changes during an individual file read are rejected, but concurrent directory changes may be missed. Baselines are not signed.

## Tests

```bash
python -m unittest discover -v
```

Tests cover content changes, empty/binary/nested files, symlinks, invalid baselines, exit codes, baseline placement and overwrite protection. GitHub Actions runs the suite on Windows and Linux with Python 3.10 and 3.13.

Created with AI assistance as a cybersecurity portfolio project.
