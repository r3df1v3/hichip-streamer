# Changelog

## 0.22.0 - public release

- Removed real camera IP, wake MAC, and AES video-key defaults.
- Added `HICHIP_WAKE_MAC`, `HICHIP_VIDEO_KEY`, and `HICHIP_PRIVATE_DIR` environment-variable support.
- Moved captured bootstrap and late-session F1D0 packets out of the executable/repository.
- Added local FFmpeg discovery next to the executable before falling back to `PATH`.
- Renamed the Windows client build to `hichip-client220.exe`.
- Translated user-facing text, comments, documentation, and build output to English.
- Added public-release documentation, security guidance, and `.gitignore` rules.
