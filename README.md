# Open Aria Bridge Desktop

Open Aria Bridge Desktop is the PC-side import and transfer application for
YLX recording sessions. It discovers sessions over the device API or from
read-only media, verifies and imports them into a local repository, resumes
persistent transfer tasks, and publishes immutable objects to S3-compatible
storage.

The Python distribution and command remain named `ylx-transfer` for the
current 0.5 compatibility line.

## Requirements

- Python 3.11 or newer
- FFmpeg for stereo video normalization
- An S3-compatible object store for publication workflows

## Install

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
ylx-transfer doctor --json
```

## Test And Build

```bash
python -m unittest discover -s tests -v
python -m pip install build
python -m build
```

## Run

```bash
ylx-transfer serve --media-root /media --media-root /run/media
```

The local web interface listens on `127.0.0.1:8765` by default. Production
device and object-storage credentials are supplied through environment
variables and must not be committed to the repository.

## License

Source available. All rights reserved. See [LICENSE](LICENSE).
