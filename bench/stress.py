#!/usr/bin/env python3
"""Hostile-load scenarios for wardend (the 0.14.2 review and gate A of the
0.15 plan). Each scenario runs the daemon with a minimal configuration of its
own, drives the load, samples /proc and reads the journal and /metrics
afterwards. Results: one JSON line per scenario on stdout and a summary file.

    sudo python3 -I bench/stress.py --wardend target/profiling/wardend --only block_storm

Run as root on a disposable machine or VM: the firewall scenarios use a
table of their own (`inet wbench`), never `inet warden`, but they do add
real nftables elements and run a process that is killed.

Scenarios and what gate A of the 0.15 plan expects of 0.14.3:
  block_storm    400 new attackers/s + victims to kill: kill p99 < 50 ms,
                 no containment dropped (`warden.queue_overflow` absent)
  block_burst    10 000 attackers as fast as the log is read: all blocked in < 5 s
  block_near_cap 45 000 entries in the set: < 5 ms per address in a batch
  waf_v6_spread  4 requests per address of one /64: one block of the /64;
                 the IPv4 control (5 per address) is blocked per address
  waf_v6_unique, exec_storm, auth_unique, victims_only: load profiles
"""
import argparse, json, os, random, shutil, signal, subprocess, sys, tempfile, threading, time, urllib.request, ipaddress

BASE = """
[daemon]
dry_run = {dry}
state_dir = "{w}/state"
runtime_dir = "{w}/run"
control_socket = "{w}/run/control.sock"
log_format = "text"
log_level = "info"
mlock = false
[metrics]
enabled = true
listen = "127.0.0.1:19184"
[events]
path = "{w}/events.jsonl"
[actions]
quarantine_dir = "{w}/quarantine"
snapshot_dir = "{w}/snapshots"
[actions.firewall]
enabled = {fw}
table = "wbench"
[memory]
enabled = false
[cpu]
enabled = false
[io]
enabled = false
[stall]
enabled = false
[disk]
enabled = false
[limits]
enabled = false
[network]
enabled = false
[systemd]
enabled = false
[hardware]
enabled = false
[kernel]
enabled = false
[integrity]
enabled = false
[fim]
enabled = false
[health]
enabled = false
[tuning]
advise = false
"""

CLK = os.sysconf("SC_CLK_TCK")


def native(uid, ip, i):
    b = f"{uid:016x}"[-8:]
    return (f"--{b}-A--\n[28/Oct/2026:12:00:00 +0000] U{uid} {ip} 4{i % 9999:04d} 10.0.0.1 443\n"
            f"--{b}-B--\nGET /shell.php?cmd=id&i={i} HTTP/1.1\nHost: example.com\n\n"
            f"--{b}-F--\nHTTP/1.1 403 Forbidden\n\n"
            f"--{b}-H--\nMessage: Access denied with code 403 (phase 2). Matched phrase \"cmd=\" "
            f"[file \"/crs/REQUEST-932.conf\"] [id \"932160\"] [msg \"Remote Command Execution: Unix Shell Code Found\"] "
            f"[severity \"CRITICAL\"]\nAction: Intercepted (phase 2)\n\n--{b}-Z--\n")


def rate_loop(stop, rate, fn, batch=50):
    """Call fn(i) `rate` times a second, in batches."""
    i = 0
    t0 = time.monotonic()
    while not stop.is_set():
        fn(i, batch)
        i += batch
        d = t0 + i / rate - time.monotonic()
        if d > 0:
            stop.wait(d)


class Daemon:
    def __init__(self, wardend, w, cfg):
        self.w = w
        open(f"{w}/warden.toml", "w").write(cfg)
        chk = subprocess.run([wardend, "--check-config", "--config", f"{w}/warden.toml"], capture_output=True, text=True)
        if chk.returncode:
            raise SystemExit(chk.stdout + chk.stderr)
        self.log = open(f"{w}/daemon.log", "w")
        self.p = subprocess.Popen([wardend, "--config", f"{w}/warden.toml"], stdout=self.log, stderr=subprocess.STDOUT)
        self.samples = []
        self.stop = threading.Event()
        threading.Thread(target=self.sample, daemon=True).start()

    def cpu(self):
        f = open(f"/proc/{self.p.pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / CLK

    def status(self):
        d = {}
        for l in open(f"/proc/{self.p.pid}/status"):
            k, _, v = l.partition(":")
            d[k] = v.strip()
        return d

    def threads(self):
        out = {}
        for t in os.listdir(f"/proc/{self.p.pid}/task"):
            try:
                s = open(f"/proc/{self.p.pid}/task/{t}/stat").read()
                name = s[s.index("(") + 1:s.rindex(")")]
                f = s.rsplit(")", 1)[1].split()
                out[name] = out.get(name, 0) + (int(f[11]) + int(f[12])) / CLK
            except OSError:
                pass
        return out

    def sample(self):
        while not self.stop.is_set():
            try:
                st = self.status()
                self.samples.append({"t": time.monotonic(), "cpu": self.cpu(),
                                     "rss_kb": int(st["VmRSS"].split()[0]), "hwm_kb": int(st["VmHWM"].split()[0]),
                                     "threads": int(st["Threads"])})
            except (OSError, KeyError, ValueError):
                pass
            self.stop.wait(1)

    def metrics(self):
        try:
            txt = urllib.request.urlopen("http://127.0.0.1:19184/metrics", timeout=5).read().decode()
        except Exception as e:  # noqa
            return {"error": str(e)}
        m = {}
        for l in txt.splitlines():
            if l and not l.startswith("#"):
                k, _, v = l.rpartition(" ")
                m[k] = float(v)
        return m

    def finish(self):
        th = self.threads()
        met = self.metrics()
        self.stop.set()
        self.p.send_signal(signal.SIGTERM)
        try:
            self.p.wait(20)
        except subprocess.TimeoutExpired:
            self.p.kill()
        return th, met

    def events(self):
        out = []
        try:
            for l in open(f"{self.w}/events.jsonl"):
                try:
                    out.append(json.loads(l))
                except ValueError:
                    pass
        except OSError:
            pass
        return out


def summary(d, t_load0, t_load1, extra):
    s = d.samples
    base = [x for x in s if x["t"] <= t_load0] or s[:1]
    load = [x for x in s if t_load0 <= x["t"] <= t_load1]
    r = {}
    if base and load:
        r["cpu_load_seconds"] = round(load[-1]["cpu"] - base[-1]["cpu"], 2)
        r["cpu_load_percent_of_core"] = round(100 * (load[-1]["cpu"] - base[-1]["cpu"]) / max(1e-9, load[-1]["t"] - base[-1]["t"]), 1)
        r["rss_before_mib"] = round(base[-1]["rss_kb"] / 1024, 1)
        r["rss_after_mib"] = round(load[-1]["rss_kb"] / 1024, 1)
        r["rss_peak_mib"] = round(max(x["hwm_kb"] for x in s) / 1024, 1)
        r["threads"] = load[-1]["threads"]
    r.update(extra)
    return r


def kinds(evs):
    c = {}
    for e in evs:
        c[e["kind"]] = c.get(e["kind"], 0) + 1
    return dict(sorted(c.items(), key=lambda kv: -kv[1]))


def v6_unique(i):
    return str(ipaddress.IPv6Address((0x20010db8 << 96) | random.getrandbits(80) << 16 | (i & 0xffff)))


# ---------------------------------------------------------------- scenarios

def waf_cfg(w, block_after=5, dry="true", fw="false", extra="", proc="[process]\nenabled = false\n"):
    return BASE.format(w=w, dry=dry, fw=fw) + proc + f"""
[auth]
enabled = false
[heuristics]
enabled = true
[waf]
enabled = true
discover = false
block_after = {block_after}
window = "10m"
block = true
block_ttl = "1h"
[[waf.log]]
path = "{w}/modsec_audit.log"
site = "main"
format = "native"
""" + extra


def write_waf(path, stop, rate, ipfn, per_ip=1, counter=None):
    f = open(path, "a")
    uid = [random.getrandbits(48)]

    def fn(i, n):
        buf = []
        for k in range(i, i + n):
            ip = ipfn(k // per_ip)
            uid[0] += 1
            buf.append(native(uid[0], ip, k))
        f.write("".join(buf))
        f.flush()
        if counter is not None:
            counter[0] += n
    rate_loop(stop, rate, fn, batch=max(1, rate // 20))


def sc_waf_v6_unique(a, w):
    """N2/N3/N34: 2000 transactions/s, each from a new IPv6 address."""
    d = Daemon(a.wardend, w, waf_cfg(w))
    time.sleep(4)
    open(f"{w}/modsec_audit.log", "a").close()
    stop = threading.Event()
    n = [0]
    t0 = time.monotonic()
    th = threading.Thread(target=write_waf, args=(f"{w}/modsec_audit.log", stop, a.rate or 2000, v6_unique, 1, n), daemon=True)
    th.start()
    perf = maybe_perf(a, d, w, "waf_v6_unique")
    time.sleep(a.duration)
    stop.set(); th.join()
    t1 = time.monotonic()
    time.sleep(5)  # let it drain
    thr, met = d.finish()
    evs = d.events()
    tx = met.get('warden_waf_transactions_total{intercepted="yes"}', 0)
    return summary(d, t0, t1, {"written_transactions": n[0], "processed_transactions": tx, "journal_events": len(evs),
                               "journal_events_per_second": round(len(evs) / a.duration, 1), "kinds": kinds(evs),
                               "journal_bytes": os.path.getsize(f"{w}/events.jsonl"),
                               "thread_cpu": thr, "dropped": {k: v for k, v in met.items() if "dropped" in k or "evicted" in k},
                               "perf": perf})


def sc_waf_v6_spread(a, w):
    """N25: an attacker in one /64 sends 4 blocked requests per address (block_after = 5)."""
    d = Daemon(a.wardend, w, waf_cfg(w))
    time.sleep(4)
    open(f"{w}/modsec_audit.log", "a").close()
    stop = threading.Event()
    pfx = 0x20010db8_00aa_0001 << 64

    def ip(k):
        return str(ipaddress.IPv6Address(pfx | (k + 1)))
    n = [0]
    th = threading.Thread(target=write_waf, args=(f"{w}/modsec_audit.log", stop, 400, ip, 4, n), daemon=True)
    t0 = time.monotonic(); th.start()
    time.sleep(a.duration)
    stop.set(); th.join(); t1 = time.monotonic()
    time.sleep(3)
    thr, met = d.finish()
    evs = d.events()
    # control: IPv4, 5 per address
    w2 = w + "-v4"
    os.makedirs(w2, exist_ok=True)
    d2 = Daemon(a.wardend, w2, waf_cfg(w2))
    time.sleep(4)
    open(f"{w2}/modsec_audit.log", "a").close()
    stop2 = threading.Event(); n2 = [0]
    th2 = threading.Thread(target=write_waf, args=(f"{w2}/modsec_audit.log", stop2, 400,
                                                   lambda k: f"198.18.{(k >> 8) & 255}.{k & 255}", 5, n2), daemon=True)
    th2.start(); time.sleep(min(a.duration, 20)); stop2.set(); th2.join(); time.sleep(3)
    d2.finish()
    evs2 = d2.events()
    return summary(d, t0, t1, {"v6_transactions": n[0], "v6_addresses": n[0] // 4,
                               "v6_waf_attack_events": sum(e["kind"] == "security.waf_attack" for e in evs),
                               "v6_heuristics_ip_threshold": sum(e["kind"] == "heuristics.ip_threshold" for e in evs),
                               "v6_block_targets": sorted({block_target(e) for e in evs if e["kind"] == "action.block_ip"}),
                               "v6_waf_hit_events": sum(e["kind"] == "waf.hit" for e in evs),
                               "v4_control_transactions": n2[0],
                               "v4_waf_attack_events": sum(e["kind"] == "security.waf_attack" for e in evs2)})


def block_target(e):
    """`block_ip 2001:db8:aa:1::/64 → dry_run: ...` → the target."""
    return e["title"].split(" \u2192 ")[0].split(" ", 1)[-1]


def nft_reset(prefill=0):
    subprocess.run(["nft", "delete", "table", "inet", "wbench"], capture_output=True)
    if prefill:
        rules = ["table inet wbench {\n set blocklist4 { type ipv4_addr; flags timeout; size 262144; }\n"
                 " set blocklist6 { type ipv6_addr; flags timeout; size 262144; }\n}\n"]
        for c in range(0, prefill, 5000):
            els = ",".join(f"10.{100 + (i >> 16)}.{(i >> 8) & 255}.{i & 255} timeout 3600s" for i in range(c, min(prefill, c + 5000)))
            rules.append(f"add element inet wbench blocklist4 {{ {els} }}\n")
        subprocess.run(["nft", "-f", "-"], input="".join(rules), text=True, check=True)


def victims_cfg(w):
    return """
[process]
enabled = true
proc_connector = false
scan_interval = "1s"
[[process.limit]]
name = "victim"
comm = ["victimsleep"]
max_runtime = "2s"
actions = ["kill"]
"""


def run_victims(times, out):
    """Start a victim at each offset (s); record how long it lived."""
    t0 = time.monotonic()
    for off in times:
        d = t0 + off - time.monotonic()
        if d > 0:
            time.sleep(d)
        p = subprocess.Popen(["/usr/local/bin/victimsleep", "600"])
        st = time.monotonic()

        def wait(p=p, st=st, off=off):
            try:
                p.wait(120)
                out.append({"offset_s": off, "lived_s": round(time.monotonic() - st, 2)})
            except subprocess.TimeoutExpired:
                p.kill(); p.wait()
                out.append({"offset_s": off, "lived_s": None, "note": "not killed within 120 s"})
        threading.Thread(target=wait, daemon=True).start()


def lane_delays(evs):
    by_id = {e["id"]: e for e in evs}
    res = {"block_ip": [], "kill": []}
    for e in evs:
        if e["kind"] in ("action.block_ip", "action.kill"):
            c = by_id.get(e.get("details", {}).get("cause_id"))
            if c:
                res[e["kind"][7:]].append((e["ts_ms"] - c["ts_ms"]) / 1000)
    out = {}
    for k, v in res.items():
        v.sort()
        if v:
            out[k] = {"n": len(v), "p50_s": round(v[len(v) // 2], 3), "p90_s": round(v[int(len(v) * 0.9)], 3),
                      "max_s": round(v[-1], 3)}
    return out


def statuses(evs, kind):
    c = {}
    for e in evs:
        if e["kind"] == kind:
            s = e.get("details", {}).get("status")
            c[s] = c.get(s, 0) + 1
    return c


def sc_block_storm(a, w):
    """N23: 400 new IPv4 attackers/s (5 blocked requests each), real nft; victims to kill at 10/20/30 s."""
    shutil.copy("/bin/sleep", "/usr/local/bin/victimsleep")
    nft_reset()
    cfg = waf_cfg(w, dry="false", fw="true", proc=victims_cfg(w))
    d = Daemon(a.wardend, w, cfg)
    time.sleep(4)
    open(f"{w}/modsec_audit.log", "a").close()
    stop = threading.Event(); n = [0]
    rate = a.rate or 2000
    th = threading.Thread(target=write_waf, args=(f"{w}/modsec_audit.log", stop, rate,
                                                  lambda k: f"198.18.{(k >> 8) & 255}.{k & 255}" if k < 65536 else f"198.19.{(k >> 8) & 255}.{k & 255}", 5, n), daemon=True)
    victims = []
    t0 = time.monotonic(); th.start()
    run_victims([10, 20, 30], victims)
    time.sleep(max(0, a.duration - (time.monotonic() - t0)))
    stop.set(); th.join(); t1 = time.monotonic()
    time.sleep(15)
    thr, met = d.finish()
    evs = d.events()
    blocked = subprocess.run(["nft", "-j", "list", "set", "inet", "wbench", "blocklist4"], capture_output=True, text=True).stdout
    try:
        nblk = sum(len(x["set"].get("elem", [])) for x in json.loads(blocked)["nftables"] if "set" in x)
    except Exception:  # noqa
        nblk = None
    nft_reset()
    return summary(d, t0, t1, {"transactions": n[0], "attackers": n[0] // 5, "victims": victims,
                               "waf_attack_events": sum(e["kind"] == "security.waf_attack" for e in evs),
                               "block_ip_status": statuses(evs, "action.block_ip"),
                               "kill_status": statuses(evs, "action.kill"),
                               "limit_events": sum(e["kind"] == "process.limit_exceeded" for e in evs),
                               "lane_delay": lane_delays(evs), "in_nft_set": nblk,
                               "queue_dropped": {k: v for k, v in met.items() if "queue_dropped" in k or "events_dropped" in k},
                               "queue_overflow_events": sum(e["kind"] == "warden.queue_overflow" for e in evs),
                               "nft_batches": met.get("warden_firewall_batches_total"),
                               "thread_cpu": thr})


def sc_block_burst(a, w):
    """Gate A: 10 000 attackers (5 blocked requests each) written as fast as possible; how long until all are blocked."""
    nft_reset()
    cfg = waf_cfg(w, dry="false", fw="true")
    cfg = cfg.replace("[actions.firewall]\nenabled = true", "[actions.firewall]\nenabled = true\nmax_blocks_per_hour = 20000")
    d = Daemon(a.wardend, w, cfg)
    time.sleep(4)
    log = f"{w}/modsec_audit.log"
    open(log, "a").close()
    attackers = 10_000
    f = open(log, "a")
    uid = random.getrandbits(48)
    t0 = time.monotonic()
    chunk = []
    for k in range(attackers * 5):
        uid += 1
        chunk.append(native(uid, f"198.18.{(k // 5 >> 8) & 255}.{(k // 5) & 255}", k))
        if len(chunk) >= 5000:
            f.write("".join(chunk))
            f.flush()
            chunk = []
    f.write("".join(chunk))
    f.close()
    written = time.monotonic() - t0
    deadline = time.monotonic() + 120

    def results():
        try:
            return sum('"action.block_ip"' in line for line in open(f"{w}/events.jsonl"))
        except OSError:
            return 0
    while results() < attackers and time.monotonic() < deadline:
        time.sleep(0.5)
    t1 = time.monotonic()
    thr, met = d.finish()
    evs = d.events()
    blk = sorted(e["ts_ms"] for e in evs if e["kind"] == "action.block_ip")
    att = sorted(e["ts_ms"] for e in evs if e["kind"] == "security.waf_attack")
    nft_reset()
    return summary(d, t0, t1, {"attackers": attackers, "write_s": round(written, 2),
                               "waf_attack_events": len(att), "block_ip_status": statuses(evs, "action.block_ip"),
                               "first_attack_to_last_block_s": round((blk[-1] - att[0]) / 1000, 2) if blk and att else None,
                               "first_to_last_block_s": round((blk[-1] - blk[0]) / 1000, 2) if blk else None,
                               "lane_delay": lane_delays(evs), "nft_batches": met.get("warden_firewall_batches_total"),
                               "queue_overflow_events": sum(e["kind"] == "warden.queue_overflow" for e in evs),
                               "thread_cpu": thr})


def sc_victims_only(a, w):
    """Baseline for block_storm: the same victims, no storm."""
    shutil.copy("/bin/sleep", "/usr/local/bin/victimsleep")
    d = Daemon(a.wardend, w, waf_cfg(w, dry="false", fw="false", proc=victims_cfg(w)))
    time.sleep(4)
    victims = []
    t0 = time.monotonic()
    run_victims([2, 6, 10], victims)
    time.sleep(16)
    d.finish()
    evs = d.events()
    return summary(d, t0, time.monotonic(), {"victims": victims, "lane_delay": lane_delays(evs)})


def sc_block_near_cap(a, w):
    """N11: the set holds 45 000 entries (max_blocked = 50 000); 0.14.2 listed both sets on every block."""
    nft_reset(prefill=45000)
    cfg = waf_cfg(w, dry="false", fw="true", extra="")
    cfg = cfg.replace("[actions.firewall]\nenabled = true", "[actions.firewall]\nenabled = true\nmax_blocked = 50000")
    d = Daemon(a.wardend, w, cfg)
    time.sleep(4)
    open(f"{w}/modsec_audit.log", "a").close()
    stop = threading.Event(); n = [0]
    th = threading.Thread(target=write_waf, args=(f"{w}/modsec_audit.log", stop, 250,
                                                  lambda k: f"198.18.{(k >> 8) & 255}.{k & 255}", 5, n), daemon=True)
    t0 = time.monotonic(); th.start()
    time.sleep(a.duration)
    stop.set(); th.join(); t1 = time.monotonic()
    time.sleep(10)
    thr, met = d.finish()
    evs = d.events()
    nft_reset()
    sec = met.get("warden_firewall_batch_seconds_total")
    nb = met.get("warden_firewall_batched_blocks_total")
    return summary(d, t0, t1, {"attackers": n[0] // 5, "block_ip_status": statuses(evs, "action.block_ip"),
                               "lane_delay": lane_delays(evs), "nft_batches": met.get("warden_firewall_batches_total"),
                               "ms_per_block_in_batch": round(1000 * sec / nb, 3) if sec and nb else None,
                               "thread_cpu": thr})


def sc_exec_storm(a, w):
    """N14: 400 exec/s from one parent."""
    cfg = BASE.format(w=w, dry="true", fw="false") + """
[process]
enabled = true
proc_connector = true
[auth]
enabled = false
[waf]
enabled = false
[heuristics]
enabled = true
"""
    d = Daemon(a.wardend, w, cfg)
    time.sleep(4)
    stop = threading.Event()
    rate = a.rate or 400

    def fn(i, n):
        for k in range(n):
            if (i + k) % 2:
                subprocess.Popen(["/bin/true"]).wait()
            else:
                subprocess.Popen(["sh", "-c", "true; :"]).wait()
    th = threading.Thread(target=rate_loop, args=(stop, rate, fn, 10), daemon=True)
    m0 = d.metrics()
    t0 = time.monotonic(); th.start()
    perf = maybe_perf(a, d, w, "exec_storm")
    time.sleep(a.duration)
    stop.set(); th.join(); t1 = time.monotonic()
    time.sleep(2)
    thr, met = d.finish()
    g = lambda m, k: m.get(k, 0)  # noqa
    full = g(met, 'warden_exec_analysed_total{path="full"}')
    fast = g(met, 'warden_exec_analysed_total{path="fast"}')
    return summary(d, t0, t1, {"exec_events": g(met, "warden_exec_events_total"), "analysed_full": full, "analysed_fast": fast,
                               "vanished": g(met, "warden_exec_vanished_total"), "lost_batches": g(met, "warden_proc_events_lost_total"),
                               "thread_cpu": thr, "perf": perf})


def sc_auth_unique(a, w):
    """N3: auth.log, 2000 lines/s, a new address every 5 lines."""
    cfg = BASE.format(w=w, dry="true", fw="false") + f"""
[process]
enabled = false
[waf]
enabled = false
[heuristics]
enabled = true
[auth]
enabled = true
source = "file"
trust_file = true
auth_log = "{w}/auth.log"
"""
    open(f"{w}/auth.log", "w").close()
    d = Daemon(a.wardend, w, cfg)
    time.sleep(4)
    f = open(f"{w}/auth.log", "a")
    stop = threading.Event()

    def fn(i, n):
        buf = []
        for k in range(i, i + n):
            ip = f"192.0.{(k // 5 >> 8) & 255}.{(k // 5) & 255}" if k < 300000 else f"10.{k >> 16 & 255}.{k >> 8 & 255}.{k & 255}"
            if k % 5 == 0:
                buf.append(f"Oct 28 12:00:00 host sshd[{1000 + k}]: Failed password for invalid user u{k} from {ip} port 22 ssh2\n")
            else:
                buf.append(f"Oct 28 12:00:00 host CRON[{2000 + k}]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)\n")
        f.write("".join(buf)); f.flush()
    th = threading.Thread(target=rate_loop, args=(stop, a.rate or 2000, fn, 100), daemon=True)
    t0 = time.monotonic(); th.start()
    perf = maybe_perf(a, d, w, "auth_unique")
    time.sleep(a.duration)
    stop.set(); th.join(); t1 = time.monotonic()
    time.sleep(3)
    thr, met = d.finish()
    evs = d.events()
    return summary(d, t0, t1, {"journal_events": len(evs), "kinds": kinds(evs), "thread_cpu": thr, "perf": perf})


def maybe_perf(a, d, w, name):
    if not a.perf:
        return None
    out = f"{a.out}/{name}.perf.data"
    p = subprocess.Popen(["perf", "record", "-F", "499", "-g", "--call-graph", "dwarf,16384", "-p", str(d.p.pid), "-o", out, "--", "sleep", str(min(20, a.duration - 2))],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return out


SCENARIOS = {f.__name__[3:]: f for f in [sc_waf_v6_unique, sc_waf_v6_spread, sc_block_storm, sc_block_burst,
                                         sc_victims_only, sc_block_near_cap, sc_exec_storm, sc_auth_unique]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wardend", required=True)
    ap.add_argument("--only", default=",".join(SCENARIOS))
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--rate", type=int, default=0)
    ap.add_argument("--perf", action="store_true")
    ap.add_argument("--out", default=".")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    res = {}
    for name in a.only.split(","):
        w = tempfile.mkdtemp(prefix=f"wst-{name}-")
        os.chmod(w, 0o755)
        t = time.time()
        try:
            res[name] = SCENARIOS[name](a, w)
        except Exception as e:  # noqa
            res[name] = {"error": repr(e)}
        res[name]["wall_s"] = round(time.time() - t, 1)
        res[name]["workdir"] = w
        print(json.dumps({name: res[name]}, ensure_ascii=False), flush=True)
    json.dump(res, open(f"{a.out}/stress-{int(time.time())}.json", "w"), indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
