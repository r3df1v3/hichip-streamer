# Security

## Scope

HiChip Streamer is intended for interoperability research and operation of cameras and networks you own or are explicitly authorized to test.

## Sensitive material

Never publish camera passwords, AES/video keys, real UIDs, MAC addresses, Cloudflare tokens, packet captures containing private traffic, or the binary files under `private_material/`.

If a secret is accidentally committed, removing it in a later commit is not sufficient: rotate/revoke the secret and rewrite the repository history before publication.

## Firmware updates

Compatibility depends on observed behavior and may change with camera firmware. Keep known-working firmware/version information and research artifacts privately if long-term interoperability matters to you.
