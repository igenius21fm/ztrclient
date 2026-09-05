# routes

Your downloaded `.ztr` route configs go here. `ztrClient.py` resolves
`config_file` relative to this folder specifically — not your current
working directory, and not `ztrclient`'s top-level folder.

Get one from your dashboard's Routes panel (**Download .ztr** on a route),
then move it here:

```bash
mv ~/Downloads/<name>.ztr routes/
```

This file just keeps the folder present in git/the release zip — it's
never read by the client.
