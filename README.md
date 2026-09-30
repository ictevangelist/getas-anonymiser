# GETAs entry anonymiser

A private, password-protected portal for preparing Global EdTech Awards
entries for blind judging.

For each entry, you upload its PDFs and the names from the entry form.
Claude reads each file (text and images) and finds everything that could
identify the entrant: people, schools, trusts, companies, product names,
places, contact details, logos and photos. The portal permanently removes
them, leaving labelled black boxes such as `[school]`, strips hidden file
details and gives each entry an anonymous code such as GETA26-001.

You check each page side by side (the original with the redactions
highlighted, next to what judges will see), add anything missed or restore
anything removed by mistake, mark the entry as checked, then download all
checked entries as one zip for judges. A private key links each code back to
its entrant.

## Settings

The portal reads these environment variables:

| Variable | Purpose |
|---|---|
| `PORTAL_USERNAME` | The single login username |
| `PORTAL_PASSWORD` | Its password |
| `SECRET_KEY` | A long random string that secures the login session |
| `ANTHROPIC_API_KEY` | For Claude |
| `CODE_PREFIX` | Code prefix, default `GETA26` |
| `DATA_DIR` | Where entries are stored, default `data` (must be persistent storage) |

## Running

```bash
pip install -r requirements.txt
gunicorn app:app --workers 1 --threads 4 --timeout 120
```

Use one worker: entries are processed in background threads within it.
For local testing over plain http, also set `DEV=1`.

## Good to know

- Scanned PDFs with no text layer cannot be redacted; the portal warns you.
- On any page with an identifying logo, photo, letterhead or signature, all
  images on that page are removed.
- Changes to the "Also redact" and "Don't redact" lists apply instantly and
  cost nothing. "Ask Claude to read it again" starts a fresh AI pass.
- Claude costs roughly 10p to 30p per PDF.
- Delete entries once judging is finished: they contain personal data.
