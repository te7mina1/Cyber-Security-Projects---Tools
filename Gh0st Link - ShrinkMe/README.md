# Gh0st Link | ShrinkMe

Gh0st Link is a small desktop URL shortener built with Python and Tkinter. It accepts a destination URL and requests a shortened link from TinyURL. The interface supports copying or opening the result, validates input and provider responses, and keeps a small in-memory cache during the current run.

This is one project in the **Cyber Security Projects - Tools** collection. It is a link utility; it does not inspect or secure the destination website. Check shortened URLs before sharing or opening them, since a shortened link can conceal its destination.

## Requirements

- Python 3
- Tkinter (included with many Python distributions; on some Linux distributions it is installed separately)
- `pyshorteners`
- Internet access to contact TinyURL

## Run

From this folder, install the Python dependency if needed and launch the app:

```bash
python3 -m pip install pyshorteners
python3 shrinkMe.py
```

The application normalizes URLs without a scheme to HTTPS. Press **Ctrl+Enter** to start shortening. The application contacts TinyURL to create a link, so the destination URL is sent to that third-party service.

## Notes

- A shortened link depends on TinyURL and may stop working if the service changes or removes it.
- URL shortening does not make a destination safer or more trustworthy.
- The `local/` virtual environment and generated Python cache files are not included; install dependencies in your own environment.

