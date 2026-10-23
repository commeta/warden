//! Operator policy: suppress false positives, re-rate severity, add or
//! replace actions. Rules are evaluated in order; `suppress` always stops
//! evaluation, other effects continue unless `stop = true`.

use crate::action::{ActionSpec, de_actions};
use crate::event::{Event, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Drop the event entirely (not logged, not notified, no actions).
    Suppress,
    /// Keep the event but strip all actions (alert only).
    AlertOnly,
    /// Change the severity.
    SetSeverity,
    /// Append actions.
    AddActions,
    /// Replace the proposed actions.
    ReplaceActions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    #[serde(default)]
    pub name: Option<String>,
    /// Glob on the event kind (`security.*`, `disk.space`).
    #[serde(default = "any_kind")]
    pub kind: String,
    /// Regex on the subject string (`process sh[123] user=www-data exe=/usr/bin/dash`).
    #[serde(default)]
    pub subject: Option<String>,
    /// Regex on the event title.
    #[serde(default)]
    pub title: Option<String>,
    /// Regex per detail key (value is matched in its JSON string form).
    #[serde(default)]
    pub details: BTreeMap<String, String>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub max_severity: Option<Severity>,
    pub effect: Effect,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default, deserialize_with = "de_actions")]
    pub actions: Vec<ActionSpec>,
    #[serde(default)]
    pub stop: bool,
}

fn any_kind() -> String {
    "*".into()
}

#[derive(Debug)]
struct Compiled {
    kind: globset::GlobMatcher,
    subject: Option<Regex>,
    title: Option<Regex>,
    details: Vec<(String, Regex)>,
}

impl PolicyRule {
    pub(crate) fn compile(&self) -> Result<(), String> {
        self.compiled().map(|_| ())
    }

    fn compiled(&self) -> Result<Compiled, String> {
        let kind = globset::Glob::new(&self.kind).map_err(|e| format!("kind glob: {e}"))?.compile_matcher();
        let re = |s: &Option<String>| -> Result<Option<Regex>, String> {
            s.as_deref().map(Regex::new).transpose().map_err(|e| e.to_string())
        };
        let details = self
            .details
            .iter()
            .map(|(k, v)| Regex::new(v).map(|r| (k.clone(), r)).map_err(|e| format!("details.{k}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        if self.effect == Effect::SetSeverity && self.severity.is_none() {
            return Err("effect = \"set_severity\" requires `severity`".into());
        }
        if matches!(self.effect, Effect::AddActions | Effect::ReplaceActions) && self.actions.is_empty() {
            return Err("effect requires a non-empty `actions` list".into());
        }
        Ok(Compiled { kind, subject: re(&self.subject)?, title: re(&self.title)?, details })
    }
}

#[derive(Debug, Default)]
pub struct Policy {
    rules: Vec<(PolicyRule, Compiled)>,
}

impl Policy {
    pub fn new(rules: &[PolicyRule]) -> Result<Self, String> {
        let rules = rules.iter().map(|r| r.compiled().map(|c| (r.clone(), c))).collect::<Result<Vec<_>, _>>()?;
        Ok(Self { rules })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Apply the policy. Returns `None` when the event is suppressed.
    pub fn apply(&self, mut ev: Event) -> Option<Event> {
        let blocks = |ev: &Event| ev.actions.iter().any(|a| matches!(a, ActionSpec::BlockIp { .. }));
        for (i, (rule, c)) in self.rules.iter().enumerate() {
            if !matches(rule, c, &ev) {
                continue;
            }
            let blocked_before = blocks(&ev);
            if let Some(name) = &rule.name {
                ev.details
                    .entry("policy".into())
                    .and_modify(|v| {
                        if let Some(a) = v.as_array_mut() {
                            a.push(name.clone().into());
                        }
                    })
                    .or_insert_with(|| serde_json::json!([name]));
            }
            match rule.effect {
                Effect::Suppress => return None,
                Effect::AlertOnly => ev.actions.clear(),
                Effect::SetSeverity => {
                    if let Some(s) = rule.severity {
                        ev.severity = s;
                    }
                }
                Effect::AddActions => {
                    for a in &rule.actions {
                        if !ev.actions.contains(a) {
                            ev.actions.push(a.clone());
                        }
                    }
                }
                Effect::ReplaceActions => ev.actions = rule.actions.clone(),
            }
            // The operator took the block away, or said "alert only": the
            // heuristics must not put it back (see `event::IP_BLOCK_OFF`).
            if (blocked_before && !blocks(&ev)) || matches!(rule.effect, Effect::AlertOnly) {
                let who = rule.name.clone().unwrap_or_else(|| format!("#{}", i + 1));
                ev.details.entry(crate::event::IP_BLOCK_OFF.into()).or_insert_with(|| format!("policy {who}").into());
                // ... nor contain the process (see `event::ACTIONS_WITHHELD`)
                if matches!(rule.effect, Effect::AlertOnly) {
                    ev.details
                        .entry(crate::event::ACTIONS_WITHHELD.into())
                        .or_insert_with(|| format!("policy {who} (alert_only)").into());
                }
            }
            if rule.stop {
                break;
            }
        }
        Some(ev)
    }
}

fn matches(rule: &PolicyRule, c: &Compiled, ev: &Event) -> bool {
    if !c.kind.is_match(&ev.kind) {
        return false;
    }
    if rule.min_severity.is_some_and(|s| ev.severity < s) {
        return false;
    }
    if rule.max_severity.is_some_and(|s| ev.severity > s) {
        return false;
    }
    if let Some(re) = &c.subject
        && !re.is_match(&ev.subject.to_string())
    {
        return false;
    }
    if let Some(re) = &c.title
        && !re.is_match(&ev.title)
    {
        return false;
    }
    for (k, re) in &c.details {
        let Some(v) = ev.details.get(k) else { return false };
        let s = match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if !re.is_match(&s) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ProcessRef, Subject};

    fn rules(src: &str) -> Policy {
        #[derive(Deserialize)]
        struct W {
            policy: Vec<PolicyRule>,
        }
        let w: W = toml::from_str(src).unwrap();
        Policy::new(&w.policy).unwrap()
    }

    fn ev() -> Event {
        Event::new("security.web_spawn", Severity::Warning, "php-fpm spawned sh")
            .subject(Subject::Process(ProcessRef {
                pid: 10,
                start_time: 1,
                comm: "sh".into(),
                exe: Some("/usr/bin/dash".into()),
                user: Some("www-data".into()),
                ..Default::default()
            }))
            .detail("cmdline", "sh -c /usr/bin/backup.sh")
            .actions(vec![ActionSpec::Snapshot])
    }

    #[test]
    fn suppress_by_detail_regex() {
        let p = rules(
            r#"[[policy]]
               name = "backup cron from php"
               kind = "security.web_spawn"
               details = { cmdline = "backup\\.sh" }
               effect = "suppress""#,
        );
        assert!(p.apply(ev()).is_none());
    }

    #[test]
    fn non_matching_rule_passes_through() {
        let p = rules(
            r#"[[policy]]
               kind = "disk.*"
               effect = "suppress""#,
        );
        assert!(p.apply(ev()).is_some());
    }

    #[test]
    fn escalate_and_add_actions() {
        let p = rules(
            r#"[[policy]]
               name = "kill shells from www-data"
               kind = "security.*"
               subject = "user=www-data"
               effect = "set_severity"
               severity = "critical"
               [[policy]]
               kind = "security.web_spawn"
               effect = "add_actions"
               actions = ["kill"]"#,
        );
        let e = p.apply(ev()).unwrap();
        assert_eq!(e.severity, Severity::Critical);
        assert_eq!(e.actions.len(), 2);
        assert!(e.details["policy"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn a_policy_that_takes_the_block_away_says_so() {
        let p = rules(
            r#"[[policy]]
               name = "office NAT"
               kind = "security.ssh_bruteforce"
               effect = "replace_actions"
               actions = ["snapshot"]
               [[policy]]
               kind = "security.waf_attack"
               effect = "alert_only""#,
        );
        let ssh = Event::new("security.ssh_bruteforce", Severity::Warning, "x")
            .actions(vec![ActionSpec::BlockIp { ttl: None }]);
        let out = p.apply(ssh).unwrap();
        assert_eq!(out.details[crate::event::IP_BLOCK_OFF], "policy office NAT");
        assert!(!out.details.contains_key(crate::event::ACTIONS_WITHHELD), "replaced, not withheld");
        let waf = p.apply(Event::new("security.waf_attack", Severity::Warning, "x")).unwrap();
        assert_eq!(waf.details[crate::event::IP_BLOCK_OFF], "policy #2");
        // alert_only: the heuristics must not contain on this event either
        assert_eq!(waf.details[crate::event::ACTIONS_WITHHELD], "policy #2 (alert_only)");
        // a rule that keeps the block leaves no mark
        let other = Event::new("security.ssh_bruteforce", Severity::Warning, "x")
            .actions(vec![ActionSpec::BlockIp { ttl: None }, ActionSpec::Snapshot]);
        let keep = rules(
            r#"[[policy]]
               kind = "security.*"
               effect = "set_severity"
               severity = "critical""#,
        );
        assert!(!keep.apply(other).unwrap().details.contains_key(crate::event::IP_BLOCK_OFF));
    }

    #[test]
    fn invalid_rules_are_reported() {
        let r = PolicyRule {
            name: None,
            kind: "*".into(),
            subject: Some("(".into()),
            title: None,
            details: BTreeMap::new(),
            min_severity: None,
            max_severity: None,
            effect: Effect::Suppress,
            severity: None,
            actions: vec![],
            stop: false,
        };
        assert!(Policy::new(&[r]).is_err());
    }
}
