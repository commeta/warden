# Changelog

## 2.0.1 — LAN automation and first-run fixes

- Warden 0.14.3 is installed by default from the pinned amd64 release asset and checksum (upstream marks this tag pre-release).
- Fixed Warden release URL: GitHub release tag/asset path has no `v` prefix.
- Added `wardend.service` config validation, enable/start/restart and verification.
- Added automatic dependencies for nftables, iproute2, curl, CA certificates,
  OpenSSL, pytest and pytest-timeout; ACME gets certbot; CRS 4.x gets git.
- `apt-get update` errors now stop `apply` rather than being ignored.
- `apply` rebuilds its plan after package installation to discover package-owned
  files such as `unicode.mapping` and CRS rules. Config validators run on each apply,
  and ownership state is persisted before validation so a failed first run can be retried.
- Added `install.sh` to generate a LAN or loopback profile, install dependencies,
  apply configuration and verify services on Ubuntu Server 24.04 amd64.
- Added profile validation for IPv4/IPv6 lab networks and DNS/TLS mode input
  so bad CIDRs and missing certificates fail with actionable messages.
- ACME certificate provisioning stops active frontends for the standalone
  HTTP-01 challenge and restarts them afterwards; certificate/key pairs and
  virtual-host SANs are validated before applying the front configuration.
- Switching from ACME symlinks to supplied TLS files now replaces symlinks
  safely rather than writing through them into Certbot-managed files.
- LAN installer prints all required `hosts` aliases, including emulated site
  vhosts. LAN allow-lists normalize CIDRs and reject world-wide trust entries.
- nftables syntax is validated before service restart; the generated firewall
  replaces only the Kit-owned `inet lab_filter` table idempotently and never flushes
  the host ruleset or touches Warden's `inet warden` table.
- APT service autostarts are temporarily inhibited during dependency and Warden package installation
  so daemons start only after configuration validation. Administrator `policy-rc.d` is preserved.
- Service restart and role pre/post-apply failures are fatal (not just warnings); pending restarts survive a failed apply
  and are retried on the next run. LAN firewall denies non-trusted clients before conntrack accept.
- Replaced fake placeholder Warden checksum in profile examples with the
  published release checksum. Production example starts in observe-only mode.
- Default Warden mode remains dry-run/observe; enforcement is opt-in.
