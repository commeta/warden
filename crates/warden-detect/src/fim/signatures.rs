//! Content signatures for web malware: webshells, backdoors, droppers,
//! obfuscation and injected JavaScript. Rules are additive scores; the FIM
//! engine compares the total against `alert_score` / `quarantine_score`.
//!
//! Operators can add rules in TOML (`/etc/warden/signatures.d/*.toml`):
//!
//! ```toml
//! [[rule]]
//! id = "acme-backdoor"
//! description = "ACME specific backdoor marker"
//! score = 100
//! pattern = 'x_acme_door\('
//! files = ["*.php"]
//! ```

use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use warden_core::GlobList;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub description: String,
    pub score: u32,
    pub pattern: String,
    /// File-name globs (basename) the rule applies to; empty = all.
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RuleSpec>,
}

const PHP: &[&str] = &["*.php", "*.php[0-9]", "*.phtml", "*.pht", "*.inc", "*.module", "*.phar"];
const JS: &[&str] = &["*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts"];
const HTML: &[&str] = &["*.html", "*.htm", "*.shtml", "*.svg", "*.php", "*.phtml"];
const PY: &[&str] = &["*.py"];
const SERVERCFG: &[&str] = &[".htaccess", ".user.ini", "php.ini", "web.config"];

fn builtin() -> Vec<(&'static str, &'static str, u32, &'static str, &'static [&'static str])> {
    vec![
        // --- PHP ---
        (
            "php-eval-decode",
            "eval/assert of decoded payload",
            90,
            r"(?i)\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uudecode)\s*\(",
            PHP,
        ),
        (
            "php-exec-input",
            "code/command execution of request input",
            100,
            r"(?i)\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b",
            PHP,
        ),
        (
            "php-backtick-input",
            "backtick execution of request input",
            100,
            r"`[^`]*\$_(?:GET|POST|REQUEST|COOKIE)",
            PHP,
        ),
        (
            "php-callback-input",
            "callback invoked with request input",
            80,
            r"(?i)\b(?:call_user_func(?:_array)?|array_map|array_filter|array_walk|usort|uasort|register_shutdown_function|register_tick_function|iterator_apply)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            PHP,
        ),
        (
            "php-variable-function-input",
            "variable function called on request input",
            80,
            r"\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b",
            PHP,
        ),
        (
            "php-dynamic-function-name",
            "function name taken from request",
            80,
            r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(",
            PHP,
        ),
        (
            "php-include-input",
            "include of request-controlled path",
            70,
            r"(?i)\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            PHP,
        ),
        (
            "php-preg-e",
            "preg_replace with /e modifier",
            70,
            r#"(?i)preg_replace\s*\(\s*['"](?:/[^'"]{0,200}/|#[^'"]{0,200}#|~[^'"]{0,200}~|@[^'"]{0,200}@|!\S{0,200}!)[a-df-z]*e[a-df-z]*['"]"#,
            PHP,
        ),
        ("php-create-function", "create_function()", 30, r"(?i)\bcreate_function\s*\(", PHP),
        ("php-error-suppressed-eval", "error-suppressed eval", 40, r"@\s*eval\s*\(", PHP),
        ("php-eval-variable", "eval of a variable", 35, r"(?i)\beval\s*\(\s*\$\w+\s*\)", PHP),
        (
            "php-known-shell",
            "known webshell family marker",
            100,
            r"(?i)(?:c99shell|r57shell|b374k|wso\s*shell|\bFilesMan\b|IndoXploit|alfa\s*(?:team|shell)|weevely|0byt3m1n1|p0wny|phpspy|AnonymousFox|mini\s*shell\s*by|Sec\s*Shell|uname\s*-a\s*;\s*id\s*;)",
            &[],
        ),
        (
            "php-file-write-input",
            "writes request data to a file",
            50,
            r"(?i)(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,200}\$_(?:GET|POST|REQUEST|FILES|COOKIE)",
            PHP,
        ),
        (
            "php-upload-arbitrary-path",
            "uploader with request-controlled destination",
            60,
            r#"(?i)move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]tmp_name['"]\s*\]\s*,\s*\$_(?:GET|POST|REQUEST)"#,
            PHP,
        ),
        ("php-chr-chain", "chr() concatenation obfuscation", 50, r"(?i)(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){10,}", PHP),
        ("php-hex-string", "long hex-escaped string", 35, r"(?:\\x[0-9a-fA-F]{2}){24,}", PHP),
        ("php-long-base64", "very long base64 literal", 30, r#"['"][A-Za-z0-9+/]{1000,}={0,2}['"]"#, PHP),
        (
            "php-globals-call",
            "function call through $GLOBALS indirection",
            40,
            r#"\$GLOBALS\s*\[\s*['"][^'"]{1,40}['"]\s*\]\s*\[\s*\d+\s*\]\s*\("#,
            PHP,
        ),
        ("php-goto-spaghetti", "goto obfuscation", 40, r"(?:goto\s+\w+;\s*\w+:\s*){15,}", PHP),
        (
            "php-disable-limits",
            "disables PHP security settings at runtime",
            40,
            r#"(?i)ini_set\s*\(\s*['"](?:disable_functions|open_basedir|safe_mode|allow_url_include)['"]"#,
            PHP,
        ),
        (
            "php-remote-include",
            "includes remote URL",
            70,
            r#"(?i)\b(?:include|require)(?:_once)?\s*\(?\s*['"](?:https?|ftp|data):"#,
            PHP,
        ),
        ("php-mailer-spam", "mass-mailer behaviour", 25, r"(?i)\bmail\s*\(\s*\$_(?:POST|GET|REQUEST)", PHP),
        // --- JavaScript / Node ---
        (
            "node-exec-request",
            "child_process with request input",
            100,
            r"(?s)child_process.{0,300}\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:`[^`]*\$\{)?\s*(?:req|request|ctx\.request|ctx)\.(?:query|body|params|headers)",
            JS,
        ),
        (
            "node-eval-request",
            "eval/Function of request input",
            100,
            r"\b(?:eval|Function|vm\.runIn\w+Context|vm\.runInThisContext)\s*\(\s*(?:req|request|ctx)\.(?:query|body|params|headers)",
            JS,
        ),
        (
            "js-eval-decode",
            "eval of decoded payload",
            60,
            r"\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|Buffer\.from)\s*\(",
            JS,
        ),
        (
            "js-fromcharcode-blob",
            "String.fromCharCode blob",
            40,
            r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){40,}",
            &[],
        ),
        ("js-obfuscator-array", "javascript-obfuscator string array", 25, r"var\s+_0x[a-f0-9]{4,6}\s*=\s*\[\s*'", JS),
        (
            "js-document-write-unescape",
            "document.write(unescape()) injection",
            50,
            r"(?i)document\.write\s*\(\s*unescape\s*\(",
            HTML,
        ),
        (
            "js-skimmer",
            "payment-card skimmer behaviour",
            70,
            r#"(?is)(?:cc_?number|card_?number|cvv|cvc).{0,400}(?:btoa|atob|fetch|XMLHttpRequest|navigator\.sendBeacon|new\s+Image\(\))"#,
            &[],
        ),
        // --- Python ---
        (
            "py-exec-request",
            "exec/os.system of request input",
            100,
            r"\b(?:os\.system|os\.popen|subprocess\.(?:Popen|call|run|check_output)|exec|eval)\s*\(\s*(?:f?['\x22][^'\x22]*\{)?\s*(?:request\.(?:args|form|values|GET|POST|data|json)|flask\.request)",
            PY,
        ),
        (
            "py-exec-decode",
            "exec of decoded payload",
            80,
            r"\bexec\s*\(\s*(?:base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode)",
            PY,
        ),
        // --- JSP / ASP ---
        (
            "jsp-exec-request",
            "JSP command execution from request",
            100,
            r"Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter",
            &["*.jsp", "*.jspx"],
        ),
        (
            "asp-eval-request",
            "ASP eval of request",
            100,
            r"(?i)\beval\s*\(\s*Request(?:\.Item)?\s*[\[(]",
            &["*.asp", "*.aspx", "*.ashx"],
        ),
        // --- server configuration abuse ---
        (
            "htaccess-php-handler",
            "maps non-PHP extensions to the PHP handler",
            80,
            r"(?i)(?:AddType|AddHandler|SetHandler)\s+application/x-httpd-(?:php|ea-php)\w*(?:\s+\.(?:jpe?g|png|gif|ico|txt|bmp|webp|svg|css|js))?",
            SERVERCFG,
        ),
        ("htaccess-prepend", "auto_prepend/append_file injection", 70, r"(?i)auto_(?:prepend|append)_file", SERVERCFG),
        (
            "htaccess-redirect-spam",
            "conditional redirect by referrer/user-agent (SEO spam)",
            40,
            r"(?is)RewriteCond\s+%\{HTTP_(?:REFERER|USER_AGENT)\}.{0,200}(?:google|bing|yahoo|yandex).{0,300}RewriteRule.{0,100}https?://",
            SERVERCFG,
        ),
        // --- generic ---
        (
            "reverse-shell-oneliner",
            "reverse shell one-liner",
            90,
            r"(?:/bin/(?:ba)?sh\s+-i\s*[<>]&?\s*/dev/tcp/|\d?>&\s*/dev/tcp/\S+/\d+|\bnc\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh|socket\.socket\(.{0,200}\.connect\(.{0,200}(?:subprocess|pty\.spawn|os\.dup2))",
            &[],
        ),
        (
            "miner-stratum",
            "crypto-miner configuration",
            80,
            r"(?i)(?:stratum\+(?:tcp|ssl)://|\bxmrig\b|\bcoinhive\b|\bcryptonight\b|minexmr|supportxmr|moneroocean)",
            &[],
        ),
        (
            "downloader-chain",
            "download and execute chain",
            70,
            r"(?i)(?:curl|wget)\s+[^|;]{0,200}(?:\|\s*(?:ba)?sh|-O-\s*\|\s*(?:ba)?sh|&&\s*chmod\s+\+x)",
            &[],
        ),
    ]
}

#[derive(Debug)]
struct CompiledRule {
    id: String,
    description: String,
    score: u32,
    pattern: String,
    unicode: bool,
    /// Compiled on the first hit only (for the line number and excerpt):
    /// matching itself is done by the shared [`RegexSet`].
    re: OnceLock<Option<Regex>>,
    files: GlobList,
}

impl CompiledRule {
    fn regex(&self) -> Option<&Regex> {
        self.re.get_or_init(|| build(&self.pattern, self.unicode).ok()).as_ref()
    }
}

/// Signatures match bytes in ASCII mode (`\w`, `\s`, `.` and `(?i)` are
/// ASCII-only): web shells are ASCII, and Unicode-aware classes multiply the
/// size of the compiled automata — tens of MiB for the built-in set.
/// Patterns that need Unicode (non-ASCII classes) fall back to it.
fn build(pattern: &str, unicode: bool) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern).unicode(unicode).size_limit(32 << 20).dfa_size_limit(1 << 20).build()
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub id: String,
    pub description: String,
    pub score: u32,
    pub line: usize,
    pub excerpt: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Verdict {
    pub score: u32,
    pub hits: Vec<Hit>,
}

impl Verdict {
    pub fn add(&mut self, id: &str, description: &str, score: u32) {
        self.score = (self.score + score).min(300);
        self.hits.push(Hit { id: id.into(), description: description.into(), score, line: 0, excerpt: String::new() });
    }

    pub fn summary(&self) -> String {
        self.hits.iter().map(|h| h.id.as_str()).collect::<Vec<_>>().join(", ")
    }
}

#[derive(Debug)]
pub struct Signatures {
    rules: Vec<CompiledRule>,
    set: RegexSet,
    php: GlobList,
}

impl Signatures {
    /// No rules (placeholder until the FIM worker loads the real set).
    pub fn empty() -> Self {
        Self { rules: Vec::new(), set: RegexSet::empty(), php: GlobList::new(PHP) }
    }

    /// Built-in rules plus user rule files (glob of TOML files).
    pub fn load(extra_globs: &[String]) -> (Self, Vec<String>) {
        let mut errors = Vec::new();
        let mut specs: Vec<RuleSpec> = builtin()
            .into_iter()
            .map(|(id, d, s, p, f)| RuleSpec {
                id: id.into(),
                description: d.into(),
                score: s,
                pattern: p.into(),
                files: f.iter().map(|x| (*x).to_owned()).collect(),
            })
            .collect();
        for path in crate::integrity::expand(extra_globs) {
            match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|s| toml::from_str::<RuleFile>(&s).map_err(|e| e.to_string()))
            {
                Ok(f) => specs.extend(f.rule),
                Err(e) => errors.push(format!("{}: {e}", path.display())),
            }
        }
        // Validate each rule on its own (precise error messages), but keep
        // only the combined set compiled.
        let mut rules = Vec::new();
        for s in specs {
            let unicode = match regex_syntax_ok(&s.pattern, false) {
                Ok(()) => false,
                Err(_) => match regex_syntax_ok(&s.pattern, true) {
                    Ok(()) => true,
                    Err(e) => {
                        errors.push(format!("signature {}: {e}", s.id));
                        continue;
                    }
                },
            };
            rules.push(CompiledRule {
                files: GlobList::new(&s.files),
                id: s.id,
                description: s.description,
                score: s.score,
                pattern: s.pattern,
                unicode,
                re: OnceLock::new(),
            });
        }
        let pats: Vec<String> =
            rules.iter().map(|r| if r.unicode { r.pattern.clone() } else { format!("(?-u:{})", r.pattern) }).collect();
        let set =
            RegexSetBuilder::new(&pats).size_limit(64 << 20).dfa_size_limit(2 << 20).build().unwrap_or_else(|e| {
                errors.push(format!("signature set: {e}"));
                RegexSet::empty()
            });
        (Self { rules, set, php: GlobList::new(PHP) }, errors)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Rule patterns as compiled (`(?-u:…)` for ASCII-mode rules), for
    /// benchmarks.
    #[doc(hidden)]
    pub fn patterns(&self) -> Vec<String> {
        self.rules.iter().map(|r| if r.unicode { r.pattern.clone() } else { format!("(?-u:{})", r.pattern) }).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Score file content. `name` is the basename used for `files` filters.
    pub fn scan(&self, name: &str, data: &[u8]) -> Verdict {
        let mut v = Verdict::default();
        for idx in self.set.matches(data).into_iter() {
            let r = &self.rules[idx];
            if !r.files.is_empty() && !r.files.is_match(name) {
                continue;
            }
            let (line, excerpt) = match r.regex().and_then(|re| re.find(data)) {
                Some(m) => {
                    let line = data[..m.start()].iter().filter(|b| **b == b'\n').count() + 1;
                    let ex: String =
                        String::from_utf8_lossy(&m.as_bytes()[..m.len().min(480)]).chars().take(120).collect();
                    (line, ex)
                }
                None => (0, String::new()),
            };
            v.score = (v.score + r.score).min(300);
            v.hits.push(Hit { id: r.id.clone(), description: r.description.clone(), score: r.score, line, excerpt });
        }
        // Structural heuristics for PHP: obfuscated droppers are long,
        // dense and high-entropy.
        if self.php.is_match(name) {
            let mut max_entropy: f64 = 0.0;
            let mut longest = 0usize;
            let mut lines = 0usize;
            for l in data.split(|b| *b == b'\n') {
                lines += 1;
                longest = longest.max(l.len());
                if l.len() >= 300 {
                    max_entropy = max_entropy.max(entropy(l));
                }
            }
            if max_entropy >= 5.6 {
                v.add("php-high-entropy-line", "high-entropy code line (packed payload)", 30);
            }
            if longest >= 20_000 {
                v.add("php-giant-line", "single line longer than 20k characters", 20);
            }
            if data.trim_ascii_start().starts_with(b"<?php") && lines <= 3 && longest > 4000 {
                v.add("php-one-line-dropper", "whole file packed on one line", 20);
            }
        }
        v
    }
}

fn regex_syntax_ok(pattern: &str, unicode: bool) -> Result<(), regex::Error> {
    // Parse-only check: an NFA size limit of 0 fails *after* parsing.
    match RegexBuilder::new(pattern).unicode(unicode).size_limit(0).build() {
        Err(regex::Error::Syntax(e)) => Err(regex::Error::Syntax(e)),
        _ => Ok(()),
    }
}

/// Shannon entropy in bits per byte.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Does a file that should not be a script contain server-side code?
/// (polyglot images like `avatar.jpg` with `<?php` inside).
pub fn has_server_code(data: &[u8]) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let head = &data[..data.len().min(256 * 1024)];
    RE.get_or_init(|| build(r#"(?i)<\?php|<\?=|<%@ page|<script language="php"|<% eval"#, false).ok())
        .as_ref()
        .is_some_and(|re| re.is_match(head))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sigs() -> Signatures {
        let (s, errs) = Signatures::load(&[]);
        assert!(errs.is_empty(), "{errs:?}");
        s
    }

    #[test]
    fn all_builtin_rules_compile() {
        assert!(sigs().len() >= 35);
    }

    #[test]
    fn detects_classic_php_shells() {
        let s = sigs();
        for (name, code) in [
            ("a.php", "<?php @eval(base64_decode($_POST['x'])); ?>"),
            ("b.php", "<?php system($_GET['cmd']); ?>"),
            ("c.php", "<?php $f = $_GET['f']; $f($_POST['a']); ?>"),
            ("d.php", "<?php $_REQUEST['a']($_REQUEST['b']); ?>"),
            ("e.php", "<?php echo `$_GET[c]`; ?>"),
            ("f.php", "<?php /* FilesMan */ $default_action = 'FilesMan'; ?>"),
            ("g.phtml", "<?php assert(str_rot13($x)); eval(gzinflate(base64_decode('xyz'))); ?>"),
        ] {
            let v = s.scan(name, code.as_bytes());
            assert!(v.score >= 80, "{name}: {} {:?}", v.score, v.summary());
        }
    }

    #[test]
    fn detects_node_python_and_config_abuse() {
        let s = sigs();
        let v = s
            .scan("srv.js", b"const cp = require('child_process'); app.get('/x', (req,res)=>{ cp.exec(req.query.c) })");
        assert!(v.score >= 80, "{:?}", v.summary());
        let v = s.scan("app.py", b"import os\n@app.route('/x')\ndef x():\n    os.system(request.args['c'])\n");
        assert!(v.score >= 80, "{:?}", v.summary());
        let v = s.scan(".htaccess", b"AddType application/x-httpd-php .jpg\n");
        assert!(v.score >= 80);
        let v = s.scan(".user.ini", b"auto_prepend_file=/tmp/x.php\n");
        assert!(v.score >= 70);
    }

    #[test]
    fn clean_code_scores_zero() {
        let s = sigs();
        let wp = b"<?php\n/**\n * Front to the WordPress application.\n */\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n";
        assert_eq!(s.scan("index.php", wp).score, 0);
        let js =
            b"import express from 'express';\nconst app = express();\napp.get('/', (req, res) => res.send('hi'));\n";
        assert_eq!(s.scan("index.js", js).score, 0);
        // rule applies only to PHP files
        assert_eq!(s.scan("notes.txt", b"system($_GET['x'])").score, 0);
    }

    #[test]
    fn entropy_and_polyglots() {
        assert!(entropy(b"aaaaaaaa") < 0.1);
        let mut x: u64 = 42;
        let rnd: Vec<u8> = (0..8192)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (x >> 33) as u8
            })
            .collect();
        assert!(entropy(&rnd) > 7.0);
        assert!(has_server_code(b"\xff\xd8\xff\xe0JFIF....<?php system($_GET[1]); ?>"));
        assert!(!has_server_code(b"\x89PNG\r\n\x1a\n...."));
    }

    #[test]
    fn shipped_example_rules_are_valid() {
        let g = format!("{}/../../config/signatures/*.toml", env!("CARGO_MANIFEST_DIR"));
        let (s, errs) = Signatures::load(&[g]);
        assert!(errs.is_empty(), "{errs:?}");
        let v = s.scan("tpl.php", br#"<a href="http://x.example/p">buy viagra</a>"#);
        assert!(v.hits.iter().any(|h| h.id == "local-seo-spam-pharma"));
    }

    #[test]
    fn user_rules_are_loaded() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("x.toml"),
            "[[rule]]\nid = 'acme'\ndescription = 'acme marker'\nscore = 100\npattern = 'acme_door\\('\nfiles = ['*.php']\n",
        )
        .unwrap();
        let (s, errs) = Signatures::load(&[format!("{}/*.toml", d.path().display())]);
        assert!(errs.is_empty());
        assert_eq!(s.scan("a.php", b"acme_door(1)").score, 100);
    }
}
