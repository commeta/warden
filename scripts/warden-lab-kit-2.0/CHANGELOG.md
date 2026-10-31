## 2.0.3 — FIM nested uploads and explicit WAF log registration

- Serial WAF and error-log modes now register one exact `[[waf.log]]` path per
  virtual host instead of relying on wildcard expansion and `{1}` substitution.
  This addresses Warden 0.14.3 doctor reports that discovered vhost logs were
  not explicitly followed when the drop-in used a wildcard source.
- The synthetic benign webshell signature was extended with recursive globs
  in its `files` filter. A follow-up source check for Warden 0.14.3 showed that
  this filter uses basenames; 2.0.4 corrects the redundant recursive entries
  and makes upload coverage explicit in each FIM site's `include` field.
- Updated unit tests to require explicit per-vhost WAF sources. (The FIM
  regression correction and expanded assertions are in 2.0.4.)

## 2.0.4 — explicit FIM upload coverage and safer WAF log trust

- Warden 0.14.3 FIM sites now receive an explicit `include` list instead of
  relying on the daemon's default. It preserves the built-in script/config
  coverage and explicitly includes direct and nested PHP-family files in
  `uploads/` so the `no_scripts` policy can flag them.
- Corrected the synthetic signature's `files` filter: Warden applies it to the
  basename, not the site-relative path. `*.php` therefore covers
  `uploads/shell-<tag>.php`; recursive path globs were removed from this field.
- The upload integration test now verifies that the HTTP 200 response really
  created the expected file and stored the exact marker before waiting for FIM.
  The PHP upload endpoint returns HTTP 500 if the write did not complete,
  rather than silently returning a false success.
- Explicitly set `waf.trust_writable_logs = false`: ModSecurity audit logs stay
  writable by Nginx (`www-data`) and are still ingested, but a web-writable log
  is no longer trusted by Warden as the sole basis for automatic IP blocking.
  The ownership warning in `wardenctl doctor` may remain by design.
- Added regression tests for explicit upload globs, basename signature
  semantics, and the WAF writable-log trust setting.

## 2.0.5 — FIM bridge for systemd private mount namespaces

- The latest clean Ubuntu 24.04 run proves that the upload endpoint creates the
  expected file and writes the exact marker bytes, while no `security.webshell`
  event arrives. This rules out the HTTP upload and marker payload, but the log
  does not yet show whether the Warden realtime sensor received the write.
- Warden 0.14.3 realtime FIM marks mounts with `FAN_MARK_MOUNT`. Ubuntu's
  `php8.3-fpm.service` and the Kit's hardened service units use filesystem
  namespace settings. Because mount marks are associated with a mount, a
  private mount view is a plausible compatibility gap; the inotify bridge is
  a conservative fallback, not yet live-verified on the user's VM.
- Added a small root-owned inotify bridge for the Kit-managed writable
  `uploads/` trees. It watches directory inodes (including nested directories),
  coalesces PHP/script/config writes, and invokes Warden's normal
  `wardenctl fim scan <site>` operation. Warden remains the authority for
  signatures, baselines, events and quarantine.
- The bridge keeps the service mount sandbox enabled; it does not disable
  `PrivateTmp`, `ProtectSystem`, `ProtectHome`, or other systemd hardening.
- The bridge coalesces file writes and rate-limits full-site scans to one per
  site every three seconds, preventing repeated upload activity from causing
  unbounded scan launches.
- The integration test now reports Warden's per-site FIM status, bridge state
  and recent bridge logs when the marker event is missing; it also performs a
  diagnostic manual scan while preserving the test failure. Unit tests cover
  nested directories, moved-in files, filtering and scan throttling.

# Changelog

## 2.0.2 — WAF vhost attribution and microservice FIM

- Every ModSecurity audit mode is now bound to virtual hosts: serial logs use a
  site-capturing glob; concurrent modes get a separate index/storage pair per
  vhost; error-log mode reads each vhost error log.
- Warden's generated `[[waf.log]]` entries carry the real virtual-host name,
  allowing WAF events and FIM/access-log correlation to identify the site.
- Microservice roots (`svc-<name>`) are registered as FIM sites, with
  `uploads/**` marked as a no-script location and the portal access log used
  for request correlation. The synthetic upload test uses unique filenames.
- Microservice source code and build outputs are root-owned and read-only to
  service accounts; only `uploads/` and `data/` remain service-writable.
  PHP-FPM pools use their service's primary group while the FastCGI socket
  remains accessible to nginx through `www-data`.
- Loopback/LAN test clients allocate unique 127/8 source addresses, avoiding
  false negatives from Warden's intentional per-peer `waf.hit` rate limit.
- WAF integration tests assert the tagged event and exact virtual-host site;
  unit tests cover WAF log rendering/post-apply and microservice ownership.
- Preserved the previous fixes for visible pytest output and idempotent
  first-start nftables loading.

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
