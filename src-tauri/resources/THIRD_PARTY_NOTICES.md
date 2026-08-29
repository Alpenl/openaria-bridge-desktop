# Third-party runtime components

## FFmpeg 8.0.1

The Windows application bundle contains the x86_64 `ffmpeg` and `ffprobe`
executables from the FFmpeg 8.0.1 essentials build produced by Gyan Doshi. The
distributed build is licensed under GPL-3.0-or-later.

- Binary provenance: https://github.com/GyanD/codexffmpeg/releases/tag/8.0.1
- Corresponding source: https://github.com/FFmpeg/FFmpeg/tree/n8.0.1
- Build manifest: `windows-ffmpeg.json`

The release workflow verifies the archive SHA-256 recorded in the build
manifest before extracting or packaging the executable.
