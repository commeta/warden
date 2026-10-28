# 0.14.3 measurements

The numbers quoted in `docs/performance.md` ("Results: 0.14.2 → 0.14.3"),
2-vCPU / 8 GiB VM, kernel 6.18, `--profile profiling` builds.

* `profile/*.json` — `sudo python3 bench/profile.py --wardend target/profiling/wardend --only idle,process,waf,all`
  (0.14.3; the 0.14.2 numbers are in `docs/reviews/review-0.14.2.ru.md`, section «Профиль»).
* `stress.jsonl` — `sudo python3 -I bench/stress.py --wardend target/profiling/wardend`, 0.14.3,
  one line per scenario.
* `stress-0.14.2.jsonl` — the same scenarios against 0.14.2 (`block_burst` did not exist yet).
