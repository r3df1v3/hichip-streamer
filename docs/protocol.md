# Protocol notes

These notes document only the portion of the observed HiChip/PPPP exchange intentionally disclosed in the first public release.

## PPPP packet types observed

| Prefix | Name |
|---|---|
| `F130` | LAN_DISCOVER |
| `F141` | LAN_HELLO |
| `F142` | LAN_HELLO_ACK |
| `F1E0` | PUNCH |
| `F1E1` | PUNCH_ACK |
| `F1F0` | SESSION_READY |
| `F1D0` | DATA |
| `F1D1` | DATA_ACK |

The camera may move to a dynamic UDP source port during the session. The client therefore follows the peer learned from received traffic instead of assuming a fixed camera port.

## Discovery behavior

The working implementation uses a persistent wake socket plus a pair of consecutive PPPP sockets. Discovery bursts are broadcast on the LAN. The exact timing values in the client are empirical and came from comparing captures of the vendor application with offline tests.

## HiChip data layer

After PPPP stabilization, the client replays an observed F1D0 command sequence. Short command packets are synthesized by the client. Device-specific opaque bootstrap and late-session packets are loaded from `private_material/` and are not included in the public repository.

This is intentional: their semantics and relationship to credentials/session state are not yet sufficiently understood to publish them as generic protocol constants.

## D1/02 media channel

Video arrives in PPPP `F1D0` packets on channel D1/02. The implementation:

1. ACKs D102 packets promptly with F1D1.
2. Tracks 16-bit packet sequence numbers.
3. Ignores duplicates and late retransmissions.
4. Drops a partial HXVF record after a detected gap.
5. Reassembles HXVF records and extracts their media payload.

## HXVF and HEVC

The tested device carries Annex-B HEVC inside HXVF records. A clean decoder start requires VPS/SPS/PPS plus an IRAP picture. The extractor waits for such a random-access point after startup or packet loss rather than feeding orphan P-frames to FFmpeg.

The tested stream was 2304x1296 HEVC at approximately 12.5 fps.

## Video encryption observation

On the tested device, the encrypted I-frame portion is limited to the first 96 bytes aligned to AES blocks. The validated transformation is AES-128 ECB followed by XOR `0x3F` on the decrypted bytes. The AES key is device/session-specific and is not included in this repository.

## HLS pipeline

The current pipeline sends reconstructed HEVC to FFmpeg asynchronously. FFmpeg transcodes to H.264 1280x720 and forces regular IDR boundaries for independent HLS segments. The queue between the UDP loop and FFmpeg prevents encoder back-pressure from blocking D102 ACK processing.
