# Development history

## Starting point

The original camera integration depended on the vendor Android application running inside NOX on a Windows VM. Automation launched the application with ADB, waited for the live view, dismissed UI elements, captured a screenshot, cropped it with ImageMagick, and copied both a current image and timestamped images to a Raspberry Pi.

That worked, but it was fragile and depended on the vendor application and emulator.

## Reverse engineering

Analysis of the application and network captures identified a PPPP-based LAN transport and a HiChip application layer. Repeated offline captures were compared until the LAN discovery, socket behavior, handshake, F1D0/F1D1 exchange, and media channel could be reproduced without Internet access.

The media path was then decoded as D102 -> HXVF -> HEVC. Packet sequencing and reassembly were refined until clean HEVC could be extracted without gaps or stale retransmissions.

## Encryption

Offline analysis established the transformation used on the encrypted prefix of I-frames: AES-128 ECB plus XOR `0x3F`. Only the first 96 bytes of the relevant frame payload required this transformation on the tested camera.

## Live streaming

Early HLS experiments attempted to copy HEVC directly. The final design instead transcodes to H.264 1280x720 with regular IDR frames and two-second HLS segments. FFmpeg runs behind an asynchronous queue so the UDP receive/ACK loop never waits for the transcoder.

An integrated HTTP server was added to serve the rolling HLS playlist and transport-stream segments. The application was then adapted for continuous Windows-service operation with rotating logs and a video watchdog.

## Deployment

In the working installation, the Windows streamer serves HLS over the LAN. A Raspberry Pi running Nginx reverse-proxies that HLS path alongside a Node-RED dashboard. A Cloudflare Tunnel terminates the public path at Nginx, which routes dashboard, static-capture, and camera requests to their respective local services.

The old NOX/ADB screenshot chain can therefore be removed completely. Still-image and timelapse generation can take frames directly from the HLS stream with FFmpeg.

## Public-release preparation

v0.22.0 removes real camera IP/MAC defaults and the embedded AES video key. It also removes captured opaque bootstrap and late-session F1D0 packets from the repository. Those files remain external private material until their semantics and credential/session relationship are better understood.

All user-facing strings, comments, documentation, and build messages were converted to English for the public repository.


## v0.22.1: resilient DHCP rediscovery

A long-running deployment exposed a reconnect bug: after the camera obtained a new DHCP address, the streamer continued receiving valid LAN `F141` replies but ignored them because their source IP no longer matched the configured `--camera-ip`. v0.22.1 changes the configured address into a preferred hint by default and adopts the newly discovered endpoint. `--strict-camera-ip` restores fixed-IP matching for networks with multiple compatible cameras.

## v0.22.2: resilient live HLS playback

Testing through the public Cloudflare route confirmed that neither the live playlist nor transport-stream segments were cached. The more likely failure mode was the original 12-second rolling playlist: a briefly delayed player could request a segment after FFmpeg had already deleted it. v0.22.2 changes the defaults to 15 two-second playlist entries and retains 10 recently unreferenced segments before deletion, providing roughly 50 seconds of total segment availability while normal playback remains near the live edge.
