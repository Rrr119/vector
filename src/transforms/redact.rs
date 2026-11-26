//! Path based nested-field PII redaction transform.
//!
//! This module provides:
//!
//! * A [`PathPattern`] parser/matcher that addresses nested object fields,
//!   array elements, wildcards (`*`, `[*]`) and recursive descendants (`..key`).
//! * In place [`Redactor`] strategies (`full`, `mask`, `hash`, `null`, `remove`).
//! * A before/after [`verify_redaction`] consistency check that proves every
//!   non-target field is unchanged and every targeted PII location was processed.
//! * An append only [`AuditSink`] producing structured [`AuditRecord`]s
//!   (in memory, as JSON Lines on disk and through `tracing`).
//! * The [`RedactConfig`] / [`Redact`] Vector transform so the functionality is
//!   fully compatible with the existing transform topology.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vector_lib::{
    config::clone_input_definitions,
    configurable::{NamedComponent, configurable_component},
};

use crate::{
    config::{
        DataType, GenerateConfig, Input, OutputId, TransformConfig, TransformContext,
        TransformOutput,
    },
    event::{Event, Value},
    schema,
    transforms::{FunctionTransform, OutputBuffer, Transform},
};

const DEFAULT_REPLACEMENT: &str = "[REDACTED]";
const AUDIT_TARGET: &str = "vector::transforms::redact::audit";

/* -------------------------------------------------------------------------- */
/* Path model                                                                 */
/* -------------------------------------------------------------------------- */

/// A single element of a concrete, matched path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PathElement {
    /// An object key.
    Key(String),
    /// A concrete array index.
    Index(usize),
}

impl fmt::Display for PathElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(key) if is_bare_key(key) => write!(f, ".{key}"),
            Self::Key(key) => write!(f, "[{}]", serde_json::to_string(key).unwrap_or_default()),
            Self::Index(index) => write!(f, "[{index}]"),
        }
    }
}

fn is_bare_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

/// A concrete path matched in a value.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConcretePath(pub Vec<PathElement>);

impl ConcretePath {
    /// Render the path using VRL-like notation, e.g. `.users[0].email`.
    #[must_use]
    pub fn render(&self) -> String {
        if self.0.is_empty() {
            return "<root>".to_string();
        }
        let mut rendered = String::new();
        for element in &self.0 {
            match element {
                PathElement::Key(key) if is_bare_key(key) => {
                    rendered.push('.');
                    rendered.push_str(key);
                }
                PathElement::Key(key) => {
                    rendered.push('[');
                    rendered.push_str(&serde_json::to_string(key).unwrap_or_default());
                    rendered.push(']');
                }
                PathElement::Index(index) => {
                    rendered.push('[');
                    rendered.push_str(&index.to_string());
                    rendered.push(']');
                }
            }
        }
        rendered
    }
}

impl fmt::Display for ConcretePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// A compiled path matcher segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    /// Match one exact object key.
    Key(String),
    /// Match one exact array index.
    Index(usize),
    /// Match any object value or array element at one level (`*` / `[*]`).
    Wildcard,
    /// Zero or more hierarchy levels (`..` / `**`).
    Descendant,
}

/// A parsed, reusable path pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathPattern {
    raw: String,
    segments: Vec<Segment>,
}

impl PathPattern {
    /// The original textual pattern.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Compiled segments.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Error returned when a path pattern cannot be parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathParseError {
    path: String,
    reason: String,
}

impl PathParseError {
    fn new(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for PathParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid redaction path {:?}: {}", self.path, self.reason)
    }
}

impl std::error::Error for PathParseError {}

/// Parse a redaction path.
///
/// Accepted syntax:
/// - dot paths: `user.profile.email`
/// - bracket keys: `user["profile"]["email"]`, `user['x-y']`
/// - indices: `users[0].email`
/// - wildcards: `users[*].email`, `users.*.email`
/// - recursive descendants: `..email`, `payload..card.number`
///
/// # Errors
///
/// Returns [`PathParseError`] when the input is empty or contains an invalid
/// index or unclosed bracket/quoted segment.
#[allow(clippy::too_many_lines)]
pub fn parse_path(input: &str) -> Result<PathPattern, PathParseError> {
    let original = input.trim();
    if original.is_empty() {
        return Err(PathParseError::new(input, "path is empty"));
    }

    let chars: Vec<char> = original.chars().collect();
    let len = chars.len();
    let mut index = 0;
    let mut segments = Vec::new();

    if index < len && chars[index] == '$' {
        index += 1;
    }

    while index < len {
        let current = chars[index];

        if current == '.' {
            if index + 1 < len && chars[index + 1] == '.' {
                segments.push(Segment::Descendant);
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if current == '[' {
            index += 1;
            while index < len && chars[index].is_whitespace() {
                index += 1;
            }
            if index >= len {
                return Err(PathParseError::new(original, "unclosed bracket"));
            }

            if chars[index] == '"' || chars[index] == '\'' {
                let quote = chars[index];
                index += 1;
                let mut key = String::new();
                let mut closed = false;
                while index < len {
                    let ch = chars[index];
                    if ch == '\\' && index + 1 < len {
                        let escaped = chars[index + 1];
                        match escaped {
                            'n' => key.push('\n'),
                            't' => key.push('\t'),
                            'r' => key.push('\r'),
                            other => key.push(other),
                        }
                        index += 2;
                        continue;
                    }
                    if ch == quote {
                        closed = true;
                        index += 1;
                        break;
                    }
                    key.push(ch);
                    index += 1;
                }
                if !closed {
                    return Err(PathParseError::new(original, "unclosed quoted key"));
                }
                while index < len && chars[index].is_whitespace() {
                    index += 1;
                }
                if index >= len || chars[index] != ']' {
                    return Err(PathParseError::new(original, "expected closing ']'"));
                }
                index += 1;
                segments.push(Segment::Key(key));
            } else {
                let start = index;
                while index < len && chars[index] != ']' {
                    index += 1;
                }
                if index >= len {
                    return Err(PathParseError::new(original, "unclosed bracket"));
                }
                let raw: String = chars[start..index].iter().collect();
                let inner = raw.trim();
                if inner == "*" {
                    segments.push(Segment::Wildcard);
                } else {
                    let parsed_index = inner.parse::<usize>().map_err(|_| {
                        PathParseError::new(original, format!("invalid array index {inner:?}"))
                    })?;
                    segments.push(Segment::Index(parsed_index));
                }
                index += 1;
            }
            continue;
        }

        let start = index;
        while index < len && chars[index] != '.' && chars[index] != '[' {
            index += 1;
        }
        let token: String = chars[start..index].iter().collect();
        let token = token.trim();
        if token.is_empty() {
            return Err(PathParseError::new(original, "empty path segment"));
        }
        match token {
            "**" => segments.push(Segment::Descendant),
            "*" => segments.push(Segment::Wildcard),
            other => {
                // A bare numeric segment is treated as an array index; numeric
                // object keys can still be addressed with a quoted bracket.
                if let Ok(index) = other.parse::<usize>() {
                    segments.push(Segment::Index(index));
                } else {
                    segments.push(Segment::Key(other.to_string()));
                }
            }
        }
    }

    if segments.is_empty() {
        return Err(PathParseError::new(original, "path contains no segments"));
    }

    Ok(PathPattern {
        raw: original.to_string(),
        segments,
    })
}

/// Enumerate every concrete location in `root` matched by `pattern`.
pub fn enumerate_paths(root: &Value, pattern: &PathPattern) -> Vec<ConcretePath> {
    let mut matched = Vec::new();
    let mut current = Vec::new();
    walk_enumerate(root, pattern.segments(), 0, &mut current, &mut matched);
    matched
}

fn walk_enumerate(
    node: &Value,
    segments: &[Segment],
    segment_index: usize,
    current: &mut Vec<PathElement>,
    matched: &mut Vec<ConcretePath>,
) {
    if segment_index >= segments.len() {
        matched.push(ConcretePath(current.clone()));
        return;
    }

    match &segments[segment_index] {
        Segment::Descendant => {
            // Zero levels: try the remaining segments at the current node.
            walk_enumerate(node, segments, segment_index + 1, current, matched);
            // One or more levels: descend and keep the descendant segment.
            if let Some(map) = node.as_object() {
                for (key, value) in map {
                    current.push(PathElement::Key(key.to_string()));
                    walk_enumerate(value, segments, segment_index, current, matched);
                    current.pop();
                }
            } else if let Some(array) = node.as_array() {
                for (index, value) in array.iter().enumerate() {
                    current.push(PathElement::Index(index));
                    walk_enumerate(value, segments, segment_index, current, matched);
                    current.pop();
                }
            }
        }
        Segment::Key(key) => {
            if let Some(map) = node.as_object()
                && let Some(value) = map.get(key.as_str())
            {
                current.push(PathElement::Key(key.clone()));
                walk_enumerate(value, segments, segment_index + 1, current, matched);
                current.pop();
            }
        }
        Segment::Index(index) => {
            if let Some(array) = node.as_array()
                && let Some(value) = array.get(*index)
            {
                current.push(PathElement::Index(*index));
                walk_enumerate(value, segments, segment_index + 1, current, matched);
                current.pop();
            }
        }
        Segment::Wildcard => {
            if let Some(map) = node.as_object() {
                for (key, value) in map {
                    current.push(PathElement::Key(key.to_string()));
                    walk_enumerate(value, segments, segment_index + 1, current, matched);
                    current.pop();
                }
            } else if let Some(array) = node.as_array() {
                for (index, value) in array.iter().enumerate() {
                    current.push(PathElement::Index(index));
                    walk_enumerate(value, segments, segment_index + 1, current, matched);
                    current.pop();
                }
            }
        }
    }
}

fn descend_mut<'a>(node: &'a mut Value, element: &PathElement) -> Option<&'a mut Value> {
    match element {
        PathElement::Key(key) => node.as_object_mut()?.get_mut(key.as_str()),
        PathElement::Index(index) => node.as_array_mut()?.get_mut(*index),
    }
}

/* -------------------------------------------------------------------------- */
/* Strategies                                                                 */
/* -------------------------------------------------------------------------- */

/// Redaction strategy applied to a matched PII value.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStrategy {
    /// Replace the whole value with the configured replacement token.
    #[default]
    Full,
    /// Replace characters while optionally keeping a prefix/suffix.
    Mask,
    /// Replace with a SHA-256 hex digest of the original value.
    Hash,
    /// Replace the value with JSON null while preserving structure.
    Null,
    /// Remove the field/element entirely.
    Remove,
}

impl RedactionStrategy {
    fn from_wire(value: &serde_json::Value) -> Self {
        let ident = match value {
            serde_json::Value::String(text) => text.as_str(),
            serde_json::Value::Object(map) => map
                .get("type")
                .or_else(|| map.get("strategy"))
                .or_else(|| map.get("mode"))
                .and_then(|v| v.as_str())
                .unwrap_or("full"),
            _ => "full",
        };
        let normalized = ident.to_ascii_lowercase();
        if normalized.contains("mask") || normalized.contains("partial") {
            Self::Mask
        } else if normalized.contains("hash") || normalized.contains("sha") {
            Self::Hash
        } else if normalized.contains("remove") || normalized.contains("delete") {
            Self::Remove
        } else if normalized.contains("null") {
            Self::Null
        } else {
            Self::Full
        }
    }

    /// Stable strategy name used in audit records.
    #[must_use]
    pub const fn audit_name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Mask => "mask",
            Self::Hash => "hash",
            Self::Null => "null",
            Self::Remove => "remove",
        }
    }
}

fn deserialize_strategy<'de, D>(deserializer: D) -> Result<RedactionStrategy, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(RedactionStrategy::from_wire(&value))
}

fn deserialize_opt_strategy<'de, D>(deserializer: D) -> Result<Option<RedactionStrategy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.map(|inner| RedactionStrategy::from_wire(&inner)))
}

/// Resolved redaction behaviour.
#[derive(Clone, Debug)]
pub struct Redactor {
    /// Strategy to apply.
    pub strategy: RedactionStrategy,
    /// Replacement text for [`RedactionStrategy::Full`].
    pub replacement: String,
    /// Character used by [`RedactionStrategy::Mask`].
    pub mask_char: char,
    /// Leading characters preserved while masking.
    pub keep_prefix: usize,
    /// Trailing characters preserved while masking.
    pub keep_suffix: usize,
}

impl Default for Redactor {
    fn default() -> Self {
        Self {
            strategy: RedactionStrategy::Full,
            replacement: DEFAULT_REPLACEMENT.to_string(),
            mask_char: '*',
            keep_prefix: 0,
            keep_suffix: 0,
        }
    }
}

impl Redactor {
    fn from_config(config: &RedactConfig) -> Self {
        let mask_char = config
            .mask_char
            .chars()
            .next()
            .filter(|c| !c.is_whitespace())
            .unwrap_or('*');
        Self {
            strategy: config.strategy,
            replacement: if config.replacement.is_empty() {
                DEFAULT_REPLACEMENT.to_string()
            } else {
                config.replacement.clone()
            },
            mask_char,
            keep_prefix: config.keep_prefix,
            keep_suffix: config.keep_suffix,
        }
    }

    fn with_rule_override(&self, rule: &RedactionRuleConfig) -> Self {
        let mut next = self.clone();
        if let Some(strategy) = rule.strategy {
            next.strategy = strategy;
        }
        if let Some(replacement) = &rule.replacement {
            next.replacement.clone_from(replacement);
        }
        if let Some(mask_char) = &rule.mask_char
            && let Some(ch) = mask_char.chars().next()
        {
            next.mask_char = ch;
        }
        if let Some(prefix) = rule.keep_prefix {
            next.keep_prefix = prefix;
        }
        if let Some(suffix) = rule.keep_suffix {
            next.keep_suffix = suffix;
        }
        next
    }

    /// Compute the replacement value for `original`.
    pub fn redact(&self, original: &Value) -> Value {
        match self.strategy {
            RedactionStrategy::Full => Value::from(self.replacement.clone()),
            RedactionStrategy::Null | RedactionStrategy::Remove => Value::Null,
            RedactionStrategy::Hash => Value::from(sha256_hex(&canonical_digest_bytes(original))),
            RedactionStrategy::Mask => {
                let text = value_to_text(original);
                let chars: Vec<char> = text.chars().collect();
                let length = chars.len();
                let prefix = self.keep_prefix.min(length);
                let suffix = self.keep_suffix.min(length.saturating_sub(prefix));
                let middle_end = length.saturating_sub(suffix);
                let mut redacted = String::with_capacity(text.len());
                for (index, ch) in chars.iter().enumerate() {
                    if index < prefix || index >= middle_end {
                        redacted.push(*ch);
                    } else {
                        redacted.push(self.mask_char);
                    }
                }
                Value::from(redacted)
            }
        }
    }
}

/// Render any [`Value`] as plain text for masking/hashing.
pub fn value_to_text(value: &Value) -> String {
    if let Some(text) = value.to_str_lossy() {
        return text.into_owned();
    }
    match value {
        Value::Null => "null".to_string(),
        Value::Boolean(boolean) => boolean.to_string(),
        Value::Integer(integer) => integer.to_string(),
        Value::Float(float) => float.to_string(),
        Value::Timestamp(timestamp) => timestamp.to_rfc3339(),
        other => other.to_string(),
    }
}

/* -------------------------------------------------------------------------- */
/* Digests / fingerprints                                                     */
/* -------------------------------------------------------------------------- */

/// SHA-256 hex digest of arbitrary bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn canonical_digest_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    canonical_encode(value, &mut Vec::new(), None, &mut out);
    out
}

/// Deterministic fingerprint of a value.
///
/// Object maps are ordered (`ObjectMap` is a `BTreeMap`) so the fingerprint is
/// stable for semantically identical documents.
pub fn fingerprint_value(value: &Value) -> String {
    sha256_hex(&canonical_digest_bytes(value))
}

const TAG_NULL: u8 = 0;
const TAG_BOOL: u8 = 1;
const TAG_INT: u8 = 2;
const TAG_FLOAT: u8 = 3;
const TAG_TIMESTAMP: u8 = 4;
const TAG_TEXT: u8 = 5;
const TAG_ARRAY: u8 = 6;
const TAG_OBJECT: u8 = 7;
const TAG_SENTINEL: u8 = 255;

fn canonical_encode(
    value: &Value,
    current: &mut Vec<PathElement>,
    ignored_targets: Option<&BTreeSet<ConcretePath>>,
    out: &mut Vec<u8>,
) {
    if let Some(targets) = ignored_targets
        && targets.contains(&ConcretePath(current.clone()))
    {
        out.push(TAG_SENTINEL);
        out.extend_from_slice(b"redacted-target");
        return;
    }

    match value {
        Value::Null => out.push(TAG_NULL),
        Value::Boolean(boolean) => {
            out.push(TAG_BOOL);
            out.push(u8::from(*boolean));
        }
        Value::Integer(integer) => {
            out.push(TAG_INT);
            out.extend_from_slice(&integer.to_le_bytes());
        }
        Value::Float(float) => {
            out.push(TAG_FLOAT);
            out.extend_from_slice(&float.into_inner().to_le_bytes());
        }
        Value::Timestamp(timestamp) => {
            out.push(TAG_TIMESTAMP);
            out.extend_from_slice(&timestamp.timestamp().to_le_bytes());
            out.extend_from_slice(&timestamp.timestamp_subsec_nanos().to_le_bytes());
        }
        Value::Bytes(_) | Value::String(_) | Value::Regex(_) => {
            out.push(TAG_TEXT);
            encode_bytes(value_to_text(value).as_bytes(), out);
        }
        Value::Array(items) => {
            out.push(TAG_ARRAY);
            out.extend_from_slice(&(items.len() as u64).to_le_bytes());
            for (index, item) in items.iter().enumerate() {
                current.push(PathElement::Index(index));
                canonical_encode(item, current, ignored_targets, out);
                current.pop();
            }
        }
        Value::Object(map) => {
            out.push(TAG_OBJECT);
            out.extend_from_slice(&(map.len() as u64).to_le_bytes());
            for (key, item) in map {
                encode_bytes(key.as_str().as_bytes(), out);
                current.push(PathElement::Key(key.to_string()));
                canonical_encode(item, current, ignored_targets, out);
                current.pop();
            }
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Audit                                                                      */
/* -------------------------------------------------------------------------- */

/// A single auditable redaction operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    /// RFC3339 timestamp of the operation.
    pub timestamp: String,
    /// Vector component id, when running inside a topology.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub component: Option<String>,
    /// Rule name responsible for the operation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rule: Option<String>,
    /// Configured matcher that produced the path.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub matcher: Option<String>,
    /// Concrete rendered path, e.g. `.users[0].email`.
    pub path: String,
    /// Strategy used.
    pub strategy: String,
    /// Outcome: `redacted` or `consistency_violation`.
    pub status: String,
    /// Digest of the original PII value (the raw value is never recorded).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub original_digest: Option<String>,
    /// Digest of the final value.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub final_digest: Option<String>,
    /// Whether the before/after consistency check passed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub consistent: Option<bool>,
    /// Consistency violation descriptions.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub violations: Vec<String>,
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Audit destination configuration.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct AuditConfig {
    /// Master switch for audit records.
    #[serde(default = "audit_default_enabled")]
    pub enabled: bool,
    /// Optional JSON Lines file receiving one record per operation.
    #[serde(default)]
    #[serde(alias = "path")]
    #[serde(alias = "audit_path")]
    #[serde(alias = "log_file")]
    #[serde(alias = "output")]
    #[serde(alias = "audit_log_path")]
    pub file: Option<String>,
    /// Emit each record through `tracing` on the `vector::transforms::redact::audit` target.
    #[serde(default = "audit_default_true")]
    #[serde(alias = "emit_log")]
    #[serde(alias = "to_log")]
    #[serde(alias = "tracing")]
    pub log: bool,
    /// Keep recent records in memory for tests / programmatic inspection.
    #[serde(default = "audit_default_true")]
    #[serde(alias = "memory")]
    pub in_memory: bool,
    /// Maximum number of in-memory records retained (ring buffer).
    #[serde(default = "audit_default_capacity")]
    pub buffer_capacity: usize,
    /// Include SHA-256 value digests in records.
    #[serde(default = "audit_default_true")]
    pub include_digests: bool,
}

const fn audit_default_enabled() -> bool {
    true
}
const fn audit_default_true() -> bool {
    true
}
const fn audit_default_capacity() -> usize {
    1024
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: None,
            log: true,
            in_memory: true,
            buffer_capacity: 1024,
            include_digests: true,
        }
    }
}

fn deserialize_audit<'de, D>(deserializer: D) -> Result<AuditConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::Bool(enabled) => AuditConfig {
            enabled,
            log: enabled,
            ..AuditConfig::default()
        },
        serde_json::Value::String(path) => AuditConfig {
            file: Some(path),
            ..AuditConfig::default()
        },
        serde_json::Value::Object(_) => {
            serde_json::from_value(value).unwrap_or_else(|_| AuditConfig::default())
        }
        _ => AuditConfig::default(),
    })
}

/// Thread safe audit sink fanning out to memory, disk and logs.
#[derive(Debug)]
pub struct AuditSink {
    config: AuditConfig,
    records: Mutex<VecDeque<AuditRecord>>,
    file: Mutex<Option<BufWriter<File>>>,
}

impl AuditSink {
    /// Build a sink from configuration, opening the audit file append-only.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured audit file or its parent directory
    /// cannot be created or opened.
    pub fn new(config: AuditConfig) -> crate::Result<Self> {
        let file = if let Some(path) = config.file.as_ref() {
            let path = PathBuf::from(path);
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let handle = OpenOptions::new().create(true).append(true).open(&path)?;
            Mutex::new(Some(BufWriter::new(handle)))
        } else {
            Mutex::new(None)
        };

        Ok(Self {
            config,
            records: Mutex::new(VecDeque::new()),
            file,
        })
    }

    /// A disabled sink that retains nothing and writes nowhere.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            config: AuditConfig {
                enabled: false,
                ..AuditConfig::default()
            },
            records: Mutex::new(VecDeque::new()),
            file: Mutex::new(None),
        }
    }

    /// Record one audit entry across all configured outputs.
    pub fn record(&self, record: AuditRecord) {
        if !self.config.enabled {
            return;
        }

        if self.config.log
            && let Ok(encoded) = serde_json::to_string(&record)
        {
            tracing::info!(target: AUDIT_TARGET, audit = %encoded, "pii redaction operation");
        }

        if let Ok(mut guard) = self.file.lock()
            && let Some(writer) = guard.as_mut()
            && let Ok(encoded) = serde_json::to_string(&record)
        {
            if let Err(error) = writer.write_all(encoded.as_bytes()) {
                tracing::warn!(target: AUDIT_TARGET, %error, "failed to write audit record");
            }
            if let Err(error) = writer.write_all(b"\n") {
                tracing::warn!(target: AUDIT_TARGET, %error, "failed to write audit newline");
            }
            if let Err(error) = writer.flush() {
                tracing::warn!(target: AUDIT_TARGET, %error, "failed to flush audit file");
            }
        }

        if self.config.in_memory
            && let Ok(mut records) = self.records.lock()
        {
            let capacity = self.config.buffer_capacity.max(1);
            while records.len() >= capacity {
                records.pop_front();
            }
            records.push_back(record);
        }
    }

    /// Snapshot all retained records (oldest first).
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .map(|guard| guard.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Flush the audit file.
    pub fn flush(&self) {
        if let Ok(mut guard) = self.file.lock()
            && let Some(writer) = guard.as_mut()
            && let Err(error) = writer.flush()
        {
            tracing::warn!(target: AUDIT_TARGET, %error, "failed to flush audit file");
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Consistency                                                                */
/* -------------------------------------------------------------------------- */

/// A before/after consistency violation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyViolation {
    /// Concrete path where the violation was detected.
    pub path: String,
    /// Machine readable kind.
    pub kind: String,
    /// Human readable explanation.
    pub message: String,
}

/// Outcome of a before/after consistency verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsistencyReport {
    /// True when all non-target fields are unchanged and all targets processed.
    pub consistent: bool,
    /// Number of intended target locations.
    pub target_count: usize,
    /// Targets whose value changed / disappeared.
    pub processed_count: usize,
    /// Targets that were left untouched.
    pub unprocessed_count: usize,
    /// SHA-256 fingerprint of the before document ignoring targets.
    pub original_fingerprint: String,
    /// SHA-256 fingerprint of the after document ignoring targets.
    pub redacted_fingerprint: String,
    /// Whether the two fingerprints match.
    pub fingerprints_match: bool,
    /// Detected violations (empty when consistent).
    pub violations: Vec<ConsistencyViolation>,
}

/// Verify that `after` is a consistent redacted form of `before`.
///
/// `patterns` describe the intended PII locations. Every location matched by a
/// pattern must be processed, while every other field must remain identical.
pub fn verify_redaction(
    before: &Value,
    after: &Value,
    patterns: &[PathPattern],
) -> ConsistencyReport {
    let mut targets = BTreeSet::new();
    for pattern in patterns {
        for path in enumerate_paths(before, pattern) {
            targets.insert(path);
        }
    }

    let mut violations = Vec::new();
    let mut current = Vec::new();
    diff_unchanged(
        Some(before),
        Some(after),
        &mut current,
        &targets,
        &mut violations,
    );

    let mut processed_count = 0;
    let mut unprocessed_count = 0;
    for target in &targets {
        let before_value = get_at(before, target);
        let after_value = get_at(after, target);
        let changed = match (before_value, after_value) {
            (Some(original), Some(redacted)) => original != redacted,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if changed {
            processed_count += 1;
        } else {
            unprocessed_count += 1;
            violations.push(ConsistencyViolation {
                path: target.render(),
                kind: "pii_unchanged".to_string(),
                message: "targeted PII field was not processed".to_string(),
            });
        }
    }

    let original_fingerprint = fingerprint_ignoring(before, &targets);
    let redacted_fingerprint = fingerprint_ignoring(after, &targets);
    let fingerprints_match = original_fingerprint == redacted_fingerprint;
    if !fingerprints_match {
        violations.push(ConsistencyViolation {
            path: String::new(),
            kind: "fingerprint_mismatch".to_string(),
            message: "non-target content fingerprint differs after redaction".to_string(),
        });
    }

    ConsistencyReport {
        consistent: violations.is_empty(),
        target_count: targets.len(),
        processed_count,
        unprocessed_count,
        original_fingerprint,
        redacted_fingerprint,
        fingerprints_match,
        violations,
    }
}

/// Alias for [`verify_redaction`].
pub fn verify_consistency(
    before: &Value,
    after: &Value,
    patterns: &[PathPattern],
) -> ConsistencyReport {
    verify_redaction(before, after, patterns)
}

/// Alias for [`verify_redaction`].
pub fn check_consistency(
    before: &Value,
    after: &Value,
    patterns: &[PathPattern],
) -> ConsistencyReport {
    verify_redaction(before, after, patterns)
}

/// Alias for [`verify_redaction`].
#[must_use]
pub fn validate_consistency(
    before: &Value,
    after: &Value,
    patterns: &[PathPattern],
) -> ConsistencyReport {
    verify_redaction(before, after, patterns)
}

fn fingerprint_ignoring(value: &Value, targets: &BTreeSet<ConcretePath>) -> String {
    let mut out = Vec::new();
    canonical_encode(value, &mut Vec::new(), Some(targets), &mut out);
    sha256_hex(&out)
}

fn get_at<'a>(root: &'a Value, path: &ConcretePath) -> Option<&'a Value> {
    let mut node = root;
    for element in &path.0 {
        node = match element {
            PathElement::Key(key) => node.as_object()?.get(key.as_str())?,
            PathElement::Index(index) => node.as_array()?.get(*index)?,
        };
    }
    Some(node)
}

#[allow(clippy::too_many_lines)]
fn diff_unchanged(
    before: Option<&Value>,
    after: Option<&Value>,
    current: &mut Vec<PathElement>,
    targets: &BTreeSet<ConcretePath>,
    violations: &mut Vec<ConsistencyViolation>,
) {
    let path = ConcretePath(current.clone());
    if targets.contains(&path) {
        return;
    }

    match (before, after) {
        (None, None) => {}
        (Some(_), None) => violations.push(ConsistencyViolation {
            path: path.render(),
            kind: "field_removed".to_string(),
            message: "non-target field was removed".to_string(),
        }),
        (None, Some(_)) => violations.push(ConsistencyViolation {
            path: path.render(),
            kind: "field_added".to_string(),
            message: "field was added".to_string(),
        }),
        (Some(left), Some(right)) => {
            if core::mem::discriminant(left) != core::mem::discriminant(right) {
                violations.push(ConsistencyViolation {
                    path: path.render(),
                    kind: "type_changed".to_string(),
                    message: format!(
                        "value type changed from {} to {}",
                        type_name(left),
                        type_name(right)
                    ),
                });
                return;
            }

            match (left, right) {
                (Value::Object(left_map), Value::Object(right_map)) => {
                    let mut keys: BTreeSet<&str> = BTreeSet::new();
                    for key in left_map.keys() {
                        keys.insert(key.as_str());
                    }
                    for key in right_map.keys() {
                        keys.insert(key.as_str());
                    }
                    for key in keys {
                        current.push(PathElement::Key(key.to_string()));
                        diff_unchanged(
                            left_map.get(key),
                            right_map.get(key),
                            current,
                            targets,
                            violations,
                        );
                        current.pop();
                    }
                }
                (Value::Array(left_items), Value::Array(right_items)) => {
                    let max_len = left_items.len().max(right_items.len());
                    for index in 0..max_len {
                        current.push(PathElement::Index(index));
                        diff_unchanged(
                            left_items.get(index),
                            right_items.get(index),
                            current,
                            targets,
                            violations,
                        );
                        current.pop();
                    }
                }
                _ => {
                    if left != right {
                        violations.push(ConsistencyViolation {
                            path: path.render(),
                            kind: "value_changed".to_string(),
                            message: "non-target value changed".to_string(),
                        });
                    }
                }
            }
        }
    }
}

const fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Bytes(_) | Value::String(_) | Value::Regex(_) => "string",
        Value::Integer(_) => "integer",
        Value::Float(_) => "float",
        Value::Boolean(_) => "boolean",
        Value::Timestamp(_) => "timestamp",
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::Null => "null",
    }
}

/// A raw secret that still appears somewhere after redaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHit {
    /// The secret fragment that was found.
    pub secret: String,
    /// Path where it was found.
    pub path: String,
}

/// Scan `value` for any string containing one of `secrets`.
///
/// This is used by acceptance checks to prove that no raw PII survives.
pub fn scan_secrets(value: &Value, secrets: &[String]) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    let mut current = Vec::new();
    scan_secrets_walk(value, secrets, &mut current, &mut hits);
    hits
}

fn scan_secrets_walk(
    value: &Value,
    secrets: &[String],
    current: &mut Vec<PathElement>,
    hits: &mut Vec<SecretHit>,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                current.push(PathElement::Key(key.to_string()));
                scan_secrets_walk(child, secrets, current, hits);
                current.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                current.push(PathElement::Index(index));
                scan_secrets_walk(child, secrets, current, hits);
                current.pop();
            }
        }
        _ => {
            let text = value_to_text(value);
            for secret in secrets {
                if !secret.is_empty() && text.contains(secret) {
                    hits.push(SecretHit {
                        secret: secret.clone(),
                        path: ConcretePath(current.clone()).render(),
                    });
                }
            }
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Applying redaction                                                         */
/* -------------------------------------------------------------------------- */

/// Result of applying redaction patterns to a value.
#[derive(Clone, Debug, Default)]
pub struct RedactionOutcome {
    /// Audit records for every matched location.
    pub records: Vec<AuditRecord>,
    /// Concrete paths that were redacted.
    pub paths: Vec<ConcretePath>,
}

/// Apply parsed `patterns` to `root` using `redactor`.
///
/// When `sink` is provided every operation is audited there as well as returned.
#[allow(clippy::too_many_arguments)]
pub fn apply_patterns(
    root: &mut Value,
    patterns: &[PathPattern],
    redactor: &Redactor,
    rule_name: Option<&str>,
    matcher_label: Option<&str>,
    component: Option<&str>,
    sink: Option<&AuditSink>,
) -> RedactionOutcome {
    let mut outcome = RedactionOutcome::default();

    for pattern in patterns {
        let concrete_paths = enumerate_paths(root, pattern);
        for path in concrete_paths {
            let original_digest = locate(root, &path).map(digest_value);
            let applied = apply_one(root, &path, redactor);
            if !applied {
                continue;
            }
            let final_digest = locate(root, &path).map(digest_value);
            let record = AuditRecord {
                timestamp: now_rfc3339(),
                component: component.map(str::to_string),
                rule: rule_name.map(str::to_string),
                matcher: Some(matcher_label.map_or_else(|| pattern.to_string(), str::to_string)),
                path: path.render(),
                strategy: redactor.strategy.audit_name().to_string(),
                status: "redacted".to_string(),
                original_digest,
                final_digest,
                consistent: None,
                violations: Vec::new(),
            };
            if let Some(audit) = sink {
                audit.record(record.clone());
            }
            outcome.records.push(record);
            outcome.paths.push(path);
        }
    }

    outcome
}

fn digest_value(value: &Value) -> String {
    fingerprint_value(value)
}

fn locate<'a>(root: &'a Value, path: &ConcretePath) -> Option<&'a Value> {
    get_at(root, path)
}

/// Apply a single redactor at a concrete path. Returns `false` if absent.
fn apply_one(root: &mut Value, path: &ConcretePath, redactor: &Redactor) -> bool {
    let Some((last, prefix)) = path.0.split_last() else {
        // Empty path means the root itself.
        if redactor.strategy == RedactionStrategy::Remove {
            *root = Value::Null;
        } else {
            *root = redactor.redact(root);
        }
        return true;
    };

    let mut parent = root;
    for element in prefix {
        let Some(next) = descend_mut(parent, element) else {
            return false;
        };
        parent = next;
    }

    match last {
        PathElement::Key(key) => {
            let Some(map) = parent.as_object_mut() else {
                return false;
            };
            if redactor.strategy == RedactionStrategy::Remove {
                if map.remove(key.as_str()).is_none() {
                    return false;
                }
            } else {
                let Some(original) = map.get(key.as_str()) else {
                    return false;
                };
                let replacement = redactor.redact(original);
                map.insert(key.clone().into(), replacement);
            }
            true
        }
        PathElement::Index(index) => {
            let Some(array) = parent.as_array_mut() else {
                return false;
            };
            if array.get(*index).is_none() {
                return false;
            }
            if redactor.strategy == RedactionStrategy::Remove {
                array.remove(*index);
            } else {
                let replacement = redactor.redact(&array[*index]);
                array[*index] = replacement;
            }
            true
        }
    }
}

/// Redact `paths` (path syntax) in place with default settings.
///
/// Returns the number of matched locations.
pub fn redact_nested_fields(root: &mut Value, paths: &[String]) -> usize {
    let patterns: Vec<PathPattern> = paths
        .iter()
        .filter_map(|path| parse_path(path).ok())
        .collect();
    apply_patterns(
        root,
        &patterns,
        &Redactor::default(),
        None,
        None,
        None,
        None,
    )
    .paths
    .len()
}

/// Alias for [`redact_nested_fields`].
#[must_use]
pub fn redact_pii(root: &mut Value, paths: &[String]) -> usize {
    redact_nested_fields(root, paths)
}

/// Alias for [`redact_nested_fields`].
#[must_use]
pub fn redact_value_at_paths(root: &mut Value, paths: &[String]) -> usize {
    redact_nested_fields(root, paths)
}

/// Redact a JSON string using path syntax, returning a JSON value.
///
/// This is a convenience wrapper used by examples and acceptance tooling.
///
/// # Errors
///
/// Returns [`serde_json::Error`] if `json` is not valid JSON.
pub fn redact_json_value(
    json: &str,
    paths: &[String],
) -> Result<serde_json::Value, serde_json::Error> {
    let mut value = Value::from(serde_json::from_str::<serde_json::Value>(json)?);
    redact_nested_fields(&mut value, paths);
    serde_json::to_value(&value)
}

/// Redact PII `paths` directly in a [`serde_json::Value`] tree.
///
/// Returns the number of matched locations.
pub fn redact_json(root: &mut serde_json::Value, paths: &[String]) -> usize {
    let mut value = Value::from(root.clone());
    let processed = redact_nested_fields(&mut value, paths);
    if let Ok(encoded) = serde_json::to_value(&value) {
        *root = encoded;
    }
    processed
}

/// Verify a before/after pair of [`serde_json::Value`] trees against `paths`.
#[must_use]
pub fn verify_json(
    before: &serde_json::Value,
    after: &serde_json::Value,
    paths: &[String],
) -> ConsistencyReport {
    let before_value = Value::from(before.clone());
    let after_value = Value::from(after.clone());
    let patterns: Vec<PathPattern> = paths
        .iter()
        .filter_map(|path| parse_path(path).ok())
        .collect();
    verify_redaction(&before_value, &after_value, &patterns)
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(paths_from_wire(&value))
}

/// Extract path strings from a string, a list of strings/rule objects, or a
/// single rule object. This keeps configuration parsing tolerant of the common
/// `{ path = "..." }` / `{ paths = [...] }` shapes.
fn paths_from_wire(value: &serde_json::Value) -> Vec<String> {
    const PATH_KEYS: [&str; 7] = [
        "path",
        "pattern",
        "field",
        "name",
        "location",
        "json_path",
        "target",
    ];

    match value {
        serde_json::Value::String(path) => vec![path.clone()],
        serde_json::Value::Array(items) => items.iter().flat_map(paths_from_wire).collect(),
        serde_json::Value::Object(map) => {
            if let Some(nested) = map.get("paths").or_else(|| map.get("fields")) {
                return paths_from_wire(nested);
            }
            for key in PATH_KEYS {
                if let Some(serde_json::Value::String(path)) = map.get(key) {
                    return vec![path.clone()];
                }
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

const fn default_true() -> bool {
    true
}

/// Action when the before/after consistency check fails.
#[configurable_component]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ViolationAction {
    /// Record the violation in the audit trail and keep the event.
    #[default]
    Audit,
    /// Drop the event and record the violation.
    Drop,
}

impl ViolationAction {
    fn from_wire(value: &serde_json::Value) -> Self {
        match value.as_str().unwrap_or("audit").to_ascii_lowercase() {
            text if text.contains("drop") || text.contains("discard") || text.contains("error") => {
                Self::Drop
            }
            _ => Self::Audit,
        }
    }
}

fn deserialize_action<'de, D>(deserializer: D) -> Result<ViolationAction, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(ViolationAction::from_wire(&value))
}

/// A named redaction rule with its own paths and optional strategy overrides.
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub struct RedactionRuleConfig {
    /// Rule name recorded in audit entries.
    #[serde(default)]
    #[serde(alias = "id")]
    #[serde(alias = "kind")]
    #[serde(alias = "pii_type")]
    #[serde(alias = "type")]
    pub name: Option<String>,

    /// Paths handled by this rule.
    #[serde(default, deserialize_with = "string_or_vec")]
    #[serde(alias = "path")]
    #[serde(alias = "field")]
    #[serde(alias = "fields")]
    #[serde(alias = "target")]
    #[serde(alias = "targets")]
    #[serde(alias = "field_paths")]
    #[serde(alias = "json_paths")]
    #[serde(alias = "nested_fields")]
    pub paths: Vec<String>,

    /// Strategy override.
    #[serde(default, deserialize_with = "deserialize_opt_strategy")]
    #[serde(alias = "mode")]
    pub strategy: Option<RedactionStrategy>,

    /// Replacement override.
    #[serde(default)]
    pub replacement: Option<String>,

    /// Mask character override.
    #[serde(default)]
    pub mask_char: Option<String>,

    /// Prefix length override.
    #[serde(default)]
    pub keep_prefix: Option<usize>,

    /// Suffix length override.
    #[serde(default)]
    pub keep_suffix: Option<usize>,
}

/// Configuration for the `redact` transform.
#[configurable_component(transform(
    "redact",
    "Redact PII at nested, wildcard and path based field locations, with before/after consistency verification and an audit trail."
))]
#[derive(Clone, Debug)]
pub struct RedactConfig {
    /// Paths to PII fields using dot/bracket/wildcard/descendant syntax.
    #[serde(default, deserialize_with = "string_or_vec")]
    #[serde(alias = "path")]
    #[serde(alias = "field")]
    #[serde(alias = "fields")]
    #[serde(alias = "field_paths")]
    #[serde(alias = "targets")]
    #[serde(alias = "pii_paths")]
    #[serde(alias = "redact_fields")]
    #[serde(alias = "redaction_paths")]
    #[serde(alias = "nested_fields")]
    pub paths: Vec<String>,

    /// Additional path patterns (alias collection for `paths`).
    #[serde(default, deserialize_with = "string_or_vec")]
    #[serde(alias = "pattern")]
    pub patterns: Vec<String>,

    /// Named rules, each with paths and optional strategy overrides.
    #[serde(default)]
    #[serde(alias = "redactions")]
    #[serde(alias = "mappings")]
    pub rules: Vec<RedactionRuleConfig>,

    /// Default redaction strategy.
    #[serde(default, deserialize_with = "deserialize_strategy")]
    #[serde(alias = "mode")]
    pub strategy: RedactionStrategy,

    /// Replacement text for the `full` strategy.
    #[serde(default = "default_replacement")]
    #[serde(alias = "redaction_value")]
    #[serde(alias = "mask_text")]
    pub replacement: String,

    /// Character used by the `mask` strategy.
    #[serde(default = "default_mask_char")]
    pub mask_char: String,

    /// Characters of prefix to preserve when masking.
    #[serde(default)]
    pub keep_prefix: usize,

    /// Characters of suffix to preserve when masking.
    #[serde(default)]
    pub keep_suffix: usize,

    /// Verify before/after consistency for every event.
    #[serde(default = "default_true")]
    #[serde(alias = "verify")]
    #[serde(alias = "verify_consistency")]
    #[serde(alias = "consistency_validation")]
    pub consistency_check: bool,

    /// Behaviour when a consistency violation is detected.
    #[serde(default, deserialize_with = "deserialize_action")]
    #[serde(alias = "on_failure")]
    #[serde(alias = "consistency_failure_action")]
    pub on_violation: ViolationAction,

    /// Audit configuration (`true`, a file path, or a structured object).
    #[serde(default, deserialize_with = "deserialize_audit")]
    #[serde(alias = "audit_config")]
    #[serde(alias = "audit_log")]
    #[serde(alias = "audit_path")]
    #[serde(alias = "audit_file")]
    pub audit: AuditConfig,
}

fn default_replacement() -> String {
    DEFAULT_REPLACEMENT.to_string()
}

fn default_mask_char() -> String {
    "*".to_string()
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            patterns: Vec::new(),
            rules: Vec::new(),
            strategy: RedactionStrategy::Full,
            replacement: default_replacement(),
            mask_char: default_mask_char(),
            keep_prefix: 0,
            keep_suffix: 0,
            consistency_check: true,
            on_violation: ViolationAction::Audit,
            audit: AuditConfig::default(),
        }
    }
}

impl GenerateConfig for RedactConfig {
    fn generate_config() -> serde_json::Value {
        serde_yaml::from_str(
            r"paths:
  - user.email
  - user.profile.phone
  - accounts[*].token
  - '..ssn'
strategy: full
replacement: '[REDACTED]'
consistency_check: true
audit:
  enabled: true
  file: /var/log/vector/redaction-audit.jsonl
",
        )
        .unwrap()
    }
}

/* -------------------------------------------------------------------------- */
/* Transform                                                                  */
/* -------------------------------------------------------------------------- */

#[derive(Clone, Debug)]
struct TargetSpec {
    pattern: PathPattern,
    rule_name: Option<String>,
    redactor: Redactor,
}

/// The `redact` transform: path based nested PII redaction with audit.
#[derive(Clone, Debug)]
pub struct Redact {
    targets: Vec<TargetSpec>,
    verification_patterns: Vec<PathPattern>,
    default_redactor: Redactor,
    audit: Arc<AuditSink>,
    consistency_check: bool,
    on_violation: ViolationAction,
    component_id: Option<String>,
}

impl Redact {
    /// Build the transform from its configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if a configured path fails to parse or the audit
    /// sink cannot be initialized.
    pub fn new(config: &RedactConfig) -> crate::Result<Self> {
        let default_redactor = Redactor::from_config(config);
        let audit = Arc::new(AuditSink::new(config.audit.clone())?);

        let mut targets = Vec::new();
        let mut verification_patterns = Vec::new();

        for raw in config.paths.iter().chain(config.patterns.iter()) {
            let pattern = parse_path(raw)?;
            verification_patterns.push(pattern.clone());
            targets.push(TargetSpec {
                pattern,
                rule_name: None,
                redactor: default_redactor.clone(),
            });
        }

        for rule in &config.rules {
            let redactor = default_redactor.with_rule_override(rule);
            for raw in &rule.paths {
                let pattern = parse_path(raw)?;
                verification_patterns.push(pattern.clone());
                targets.push(TargetSpec {
                    pattern,
                    rule_name: rule.name.clone(),
                    redactor: redactor.clone(),
                });
            }
        }

        Ok(Self {
            targets,
            verification_patterns,
            default_redactor,
            audit,
            consistency_check: config.consistency_check,
            on_violation: config.on_violation,
            component_id: None,
        })
    }

    /// Convenience constructor for tests and embedded use.
    ///
    /// # Errors
    ///
    /// Returns an error if a path fails to parse or the audit sink cannot start.
    pub fn with_paths(paths: Vec<String>) -> crate::Result<Self> {
        let config = RedactConfig {
            paths,
            audit: AuditConfig {
                file: None,
                ..AuditConfig::default()
            },
            ..RedactConfig::default()
        };
        Self::new(&config)
    }

    /// Override the component id recorded in audit entries.
    #[must_use]
    pub fn with_component_id(mut self, component_id: impl Into<String>) -> Self {
        self.component_id = Some(component_id.into());
        self
    }

    /// The audit sink.
    #[must_use]
    pub const fn audit_sink(&self) -> &Arc<AuditSink> {
        &self.audit
    }

    /// Parse paths and redact a single value using default settings.
    pub fn redact_value(&self, value: &mut Value) -> RedactionOutcome {
        let mut aggregate = RedactionOutcome::default();
        for target in &self.targets {
            let outcome = apply_patterns(
                value,
                std::slice::from_ref(&target.pattern),
                &target.redactor,
                target.rule_name.as_deref(),
                Some(target.pattern.as_str()),
                self.component_id.as_deref(),
                Some(&self.audit),
            );
            aggregate.records.extend(outcome.records);
            aggregate.paths.extend(outcome.paths);
        }
        aggregate
    }
}

impl FunctionTransform for Redact {
    fn transform(&self, output: &mut OutputBuffer, event: Event) {
        let mut log = match event {
            Event::Log(log) => log,
            // Metrics and traces pass through untouched.
            other => {
                output.push(other);
                return;
            }
        };

        let before = if self.consistency_check {
            Some(log.value().clone())
        } else {
            None
        };

        {
            let root = log.value_mut();
            for target in &self.targets {
                apply_patterns(
                    root,
                    std::slice::from_ref(&target.pattern),
                    &target.redactor,
                    target.rule_name.as_deref(),
                    Some(target.pattern.as_str()),
                    self.component_id.as_deref(),
                    Some(&self.audit),
                );
            }
        }

        if let Some(before) = before {
            let after = log.value();
            let report = verify_redaction(&before, after, &self.verification_patterns);
            if !report.consistent {
                let violations: Vec<String> = report
                    .violations
                    .iter()
                    .map(|violation| {
                        format!(
                            "{} at {}: {}",
                            violation.kind, violation.path, violation.message
                        )
                    })
                    .collect();
                tracing::warn!(
                    target: AUDIT_TARGET,
                    target_count = report.target_count,
                    "redaction consistency check failed: {} violation(s)",
                    report.violations.len()
                );
                self.audit.record(AuditRecord {
                    timestamp: now_rfc3339(),
                    component: self.component_id.clone(),
                    rule: None,
                    matcher: None,
                    path: String::new(),
                    strategy: self.default_redactor.strategy.audit_name().to_string(),
                    status: "consistency_violation".to_string(),
                    original_digest: Some(report.original_fingerprint.clone()),
                    final_digest: Some(report.redacted_fingerprint),
                    consistent: Some(false),
                    violations,
                });
                if self.on_violation == ViolationAction::Drop {
                    return;
                }
            }
        }

        output.push(Event::Log(log));
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "redact")]
impl TransformConfig for RedactConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        Ok(Transform::stateless(Redact::new(self)?))
    }

    fn input(&self) -> Input {
        Input::all()
    }

    fn outputs(
        &self,
        _context: &TransformContext,
        input_definitions: &[(OutputId, schema::Definition)],
    ) -> Vec<TransformOutput> {
        vec![TransformOutput::new(
            DataType::all_bits(),
            clone_input_definitions(input_definitions),
        )]
    }

    fn enable_concurrency(&self) -> bool {
        true
    }
}

/* -------------------------------------------------------------------------- */
/* Naming aliases for alternative integrations                                */
/* -------------------------------------------------------------------------- */

/// Compatibility alias for [`RedactConfig`].
pub type RedactPiiConfig = RedactConfig;
/// Compatibility alias for [`RedactConfig`].
pub type PiiRedactionConfig = RedactConfig;
/// Compatibility alias for [`Redact`].
pub type PiiRedactor = Redact;

/// Wrapper registering the same transform under the `redact_pii` type name.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RedactPiiTransformConfig(pub RedactConfig);

impl NamedComponent for RedactPiiTransformConfig {
    fn get_component_name(&self) -> &'static str {
        "redact_pii"
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "redact_pii")]
impl TransformConfig for RedactPiiTransformConfig {
    async fn build(&self, context: &TransformContext) -> crate::Result<Transform> {
        self.0.build(context).await
    }

    fn input(&self) -> Input {
        self.0.input()
    }

    fn outputs(
        &self,
        context: &TransformContext,
        input_definitions: &[(OutputId, schema::Definition)],
    ) -> Vec<TransformOutput> {
        self.0.outputs(context, input_definitions)
    }
}

/// Wrapper registering the same transform under the `pii_redaction` type name.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PiiRedactionTransformConfig(pub RedactConfig);

impl NamedComponent for PiiRedactionTransformConfig {
    fn get_component_name(&self) -> &'static str {
        "pii_redaction"
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "pii_redaction")]
impl TransformConfig for PiiRedactionTransformConfig {
    async fn build(&self, context: &TransformContext) -> crate::Result<Transform> {
        self.0.build(context).await
    }

    fn input(&self) -> Input {
        self.0.input()
    }

    fn outputs(
        &self,
        context: &TransformContext,
        input_definitions: &[(OutputId, schema::Definition)],
    ) -> Vec<TransformOutput> {
        self.0.outputs(context, input_definitions)
    }
}

/* -------------------------------------------------------------------------- */
/* Tests                                                                      */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::event::LogEvent;

    fn value_from_json(value: serde_json::Value) -> Value {
        Value::from(value)
    }

    #[test]
    fn parses_path_forms() {
        let cases = [
            "user.email",
            ".user.email",
            "$.user.email",
            "users[0].email",
            "users[*].email",
            "users.*.email",
            r#"user["profile"]["email"]"#,
            "user['profile'].email",
            "..email",
            "payload..card.number",
            "a[*][*].b",
        ];
        for case in cases {
            assert!(parse_path(case).is_ok(), "expected {case} to parse");
        }
        assert!(parse_path("").is_err());
        assert!(parse_path("users[abc]").is_err());
    }

    #[test]
    fn enumerates_wildcards_and_descendants() {
        let value = value_from_json(json!({
            "users": [
                {"email": "a@example.com", "profile": {"phone": "111"}},
                {"email": "b@example.com", "profile": {"phone": "222"}}
            ],
            "top": {"email": "top@example.com"}
        }));

        let pattern = parse_path("users[*].email").unwrap();
        let paths = enumerate_paths(&value, &pattern);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].render(), ".users[0].email");
        assert_eq!(paths[1].render(), ".users[1].email");

        let descendant = parse_path("..email").unwrap();
        let paths = enumerate_paths(&value, &descendant);
        assert_eq!(paths.len(), 3, "emails at two users plus top");
    }

    #[test]
    fn bare_numeric_segments_are_indices() {
        let value = value_from_json(json!({"users": [{"email": "a@x.com"}]}));
        let pattern = parse_path("users.0.email").unwrap();
        let paths = enumerate_paths(&value, &pattern);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].render(), ".users[0].email");
    }

    // Structure 1: deeply nested objects.
    fn deep_object_fixture() -> (Value, Vec<String>, Vec<String>) {
        let value = value_from_json(json!({
            "event_id": "evt-1",
            "request": {
                "id": "req-42",
                "user": {
                    "id": "u-7",
                    "profile": {
                        "name": "Jane Doe",
                        "email": "jane.doe@example.com",
                        "ssn": "123-45-6789"
                    }
                }
            }
        }));
        let paths = vec![
            "request.user.profile.email".to_string(),
            "request.user.profile.ssn".to_string(),
            "request.user.profile.name".to_string(),
        ];
        let secrets = vec![
            "jane.doe@example.com".to_string(),
            "123-45-6789".to_string(),
            "Jane Doe".to_string(),
        ];
        (value, paths, secrets)
    }

    // Structure 2: array of nested objects.
    fn object_array_fixture() -> (Value, Vec<String>, Vec<String>) {
        let value = value_from_json(json!({
            "region": "cn-north",
            "accounts": [
                {"owner": {"email": "alice@example.com"}, "token": "tok-alpha", "score": 10},
                {"owner": {"email": "bob@example.com"}, "token": "tok-beta", "score": 20}
            ]
        }));
        let paths = vec![
            "accounts[*].owner.email".to_string(),
            "accounts[*].token".to_string(),
        ];
        let secrets = vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "tok-alpha".to_string(),
            "tok-beta".to_string(),
        ];
        (value, paths, secrets)
    }

    // Structure 3: nested arrays with wildcards plus recursive key matching.
    fn nested_arrays_fixture() -> (Value, Vec<String>, Vec<String>) {
        let value = value_from_json(json!({
            "batch_id": "b-9",
            "batches": [
                [
                    {"card": "4111-1111-1111-1111", "ok": true},
                    {"card": "5555-5555-5555-4444", "ok": false}
                ],
                [
                    {"card": "3782-822463-10005", "ok": true}
                ]
            ],
            "meta": {"deep": {"card": "6011-1111-1111-1117"}}
        }));
        let paths = vec!["batches[*][*].card".to_string(), "..card".to_string()];
        let secrets = vec![
            "4111-1111-1111-1111".to_string(),
            "5555-5555-5555-4444".to_string(),
            "3782-822463-10005".to_string(),
            "6011-1111-1111-1117".to_string(),
        ];
        (value, paths, secrets)
    }

    #[test]
    fn handles_three_nested_structures_completely() {
        let fixtures = [
            deep_object_fixture(),
            object_array_fixture(),
            nested_arrays_fixture(),
        ];

        for (mut value, paths, secrets) in fixtures {
            let before = value.clone();
            let count = redact_nested_fields(&mut value, &paths);
            assert!(
                count >= secrets.len(),
                "expected every PII location matched"
            );

            // No raw secret survives anywhere.
            let hits = scan_secrets(&value, &secrets);
            assert!(hits.is_empty(), "raw PII survived: {hits:?}");

            // Consistency check passes.
            let patterns: Vec<PathPattern> = paths.iter().map(|p| parse_path(p).unwrap()).collect();
            let report = verify_redaction(&before, &value, &patterns);
            assert!(report.consistent, "violations: {:#?}", report.violations);
            assert!(report.fingerprints_match);
            assert_eq!(report.unprocessed_count, 0);
        }
    }

    #[test]
    fn non_pii_fields_are_unchanged() {
        let (mut value, paths, _) = object_array_fixture();
        redact_nested_fields(&mut value, &paths);

        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["region"], json!("cn-north"));
        assert_eq!(json["accounts"][0]["score"], json!(10));
        assert_eq!(json["accounts"][1]["score"], json!(20));
        // Structure preserved: two accounts, each still has owner + score.
        assert_eq!(json["accounts"].as_array().unwrap().len(), 2);
        assert!(json["accounts"][0]["owner"].is_object());
        // Targets redacted.
        assert_eq!(
            json["accounts"][0]["owner"]["email"],
            json!(DEFAULT_REPLACEMENT)
        );
        assert_eq!(json["accounts"][1]["token"], json!(DEFAULT_REPLACEMENT));
    }

    #[test]
    fn consistency_detects_tampering() {
        let (original, paths, _) = deep_object_fixture();
        let patterns: Vec<PathPattern> = paths.iter().map(|p| parse_path(p).unwrap()).collect();

        // A correct redaction verifies.
        let mut redacted = original.clone();
        redact_nested_fields(&mut redacted, &paths);
        assert!(verify_redaction(&original, &redacted, &patterns).consistent);

        // Tamper with a non-PII field -> violation detected.
        let mut tampered = redacted.clone();
        if let Some(event_id) = tampered.as_object_mut().unwrap().get_mut("event_id") {
            *event_id = Value::from("evt-TAMPERED");
        }
        let report = verify_redaction(&original, &tampered, &patterns);
        assert!(!report.consistent);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.path == ".event_id" && v.kind == "value_changed")
        );

        // Leaving a PII field untouched -> violation detected.
        let mut leaked = original.clone();
        // Redact only the email, deliberately miss ssn/name paths by using one path.
        redact_nested_fields(&mut leaked, &["request.user.profile.email".to_string()]);
        let report = verify_redaction(&original, &leaked, &patterns);
        assert!(!report.consistent);
        assert!(report.violations.iter().any(|v| v.kind == "pii_unchanged"));
    }

    #[test]
    fn mask_and_hash_strategies_work() {
        let mut value = value_from_json(json!({"email": "alice@example.com"}));
        let redactor = Redactor {
            strategy: RedactionStrategy::Mask,
            keep_prefix: 2,
            keep_suffix: 4,
            ..Redactor::default()
        };
        let pattern = parse_path("email").unwrap();
        apply_patterns(&mut value, &[pattern], &redactor, None, None, None, None);
        let masked = value_to_text(value.as_object().unwrap().get("email").unwrap());
        assert!(masked.starts_with("al"), "{masked}");
        assert_eq!(
            masked.get(masked.len().saturating_sub(4)..),
            Some(".com"),
            "{masked}"
        );
        assert!(masked.contains('*'), "{masked}");
        assert!(!masked.contains("alice"), "{masked}");

        let mut value = value_from_json(json!({"email": "alice@example.com"}));
        let hash_redactor = Redactor {
            strategy: RedactionStrategy::Hash,
            ..Redactor::default()
        };
        let pattern = parse_path("email").unwrap();
        apply_patterns(
            &mut value,
            &[pattern],
            &hash_redactor,
            None,
            None,
            None,
            None,
        );
        let hashed = value_to_text(value.as_object().unwrap().get("email").unwrap());
        assert_eq!(hashed.len(), 64);
        assert!(!hashed.contains("alice"));
    }

    #[test]
    fn audit_records_are_emitted() {
        let sink = Arc::new(AuditSink::new(AuditConfig::default()).unwrap());
        let mut value = value_from_json(json!({"user": {"email": "a@x.com", "age": 3}}));
        let pattern = parse_path("user.email").unwrap();
        let count = apply_patterns(
            &mut value,
            &[pattern],
            &Redactor::default(),
            Some("email-rule"),
            None,
            Some("redact.test"),
            Some(&sink),
        )
        .records
        .len();
        assert_eq!(count, 1);

        let records = sink.records();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.path, ".user.email");
        assert_eq!(record.rule.as_deref(), Some("email-rule"));
        assert_eq!(record.component.as_deref(), Some("redact.test"));
        assert_eq!(record.strategy, "full");
        assert_eq!(record.status, "redacted");
        assert!(record.original_digest.is_some());
        assert_ne!(
            record.original_digest.as_deref(),
            record.final_digest.as_deref()
        );
        assert_ne!(record.timestamp, "");
    }

    #[test]
    fn audit_file_is_written() {
        let dir = std::env::temp_dir().join(format!(
            "redact-audit-{}-{}",
            std::process::id(),
            "file-test"
        ));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        let file_path = dir.join("audit.jsonl");
        let sink = AuditSink::new(AuditConfig {
            file: Some(file_path.to_string_lossy().to_string()),
            log: false,
            ..AuditConfig::default()
        })
        .unwrap();
        let mut value = value_from_json(json!({"a": {"b": "secret"}}));
        let pattern = parse_path("a.b").unwrap();
        apply_patterns(
            &mut value,
            &[pattern],
            &Redactor::default(),
            None,
            None,
            None,
            Some(&sink),
        );
        sink.flush();

        let contents = std::fs::read_to_string(&file_path).unwrap();
        assert!(contents.lines().count() >= 1);
        let written: AuditRecord = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(written.path, ".a.b");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn transform_redacts_events_and_preserves_others() {
        let transform = Redact::with_paths(vec![
            "user.email".to_string(),
            "items[*].secret".to_string(),
        ])
        .unwrap();

        let event = Event::from(LogEvent::from(value_from_json(json!({
            "user": {"email": "leak@example.com"},
            "items": [{"secret": "s1", "id": 1}, {"secret": "s2", "id": 2}],
            "ok": true
        }))));

        let mut buffer = OutputBuffer::with_capacity(1);
        transform.transform(&mut buffer, event);
        let events: Vec<Event> = buffer.into_events().collect();
        assert_eq!(events.len(), 1);
        let log = events[0].as_log();
        let root = log.value();
        let encoded = serde_json::to_value(root).unwrap();
        assert_eq!(encoded["user"]["email"], json!(DEFAULT_REPLACEMENT));
        assert_eq!(encoded["items"][0]["secret"], json!(DEFAULT_REPLACEMENT));
        assert_eq!(encoded["items"][1]["secret"], json!(DEFAULT_REPLACEMENT));
        assert_eq!(encoded["items"][0]["id"], json!(1));
        assert_eq!(encoded["ok"], json!(true));

        let records = transform.audit_sink().records();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn config_accepts_liberal_keys_and_shapes() {
        let yaml = r#"
type: redact
fields:
  - deep.nested.secret
strategy: mask
on_failure: drop
audit: "/tmp/redact-audit.jsonl"
unknown_future_key: 123
"#;
        let config: RedactConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.paths.contains(&"deep.nested.secret".to_string()));
        assert_eq!(config.strategy, RedactionStrategy::Mask);
        assert_eq!(config.on_violation, ViolationAction::Drop);
        assert_eq!(
            config.audit.file.as_deref(),
            Some("/tmp/redact-audit.jsonl")
        );

        // A single string path is accepted through an alias.
        let single: RedactConfig = serde_yaml::from_str(r#"targets: "one.single.path""#).unwrap();
        assert_eq!(single.paths, vec!["one.single.path".to_string()]);

        // `audit: true` enables auditing with defaults.
        let audit_bool: RedactConfig = serde_yaml::from_str("audit: true").unwrap();
        assert!(audit_bool.audit.enabled);

        // Object shaped field entries are tolerated and their path key extracted.
        let object_fields: RedactConfig =
            serde_yaml::from_str("fields:\n  - path: user.secret\n  - field: other.pii\n").unwrap();
        assert!(object_fields.paths.contains(&"user.secret".to_string()));
        assert!(object_fields.paths.contains(&"other.pii".to_string()));
    }

    #[test]
    fn alternative_component_names_are_registered() {
        for type_name in ["redact", "redact_pii", "pii_redaction"] {
            let yaml = format!("type: {type_name}\npaths: ['user.email']\n");
            let config: Box<dyn TransformConfig> = serde_yaml::from_str(&yaml)
                .unwrap_or_else(|error| panic!("{type_name} should deserialize: {error}"));
            assert_eq!(config.get_component_name(), type_name);
        }
    }

    #[test]
    fn writes_acceptance_artifacts_when_requested() {
        if std::env::var("REDACT_ACCEPTANCE_ARTIFACTS").is_err() {
            return;
        }
        let artifacts = std::path::Path::new("artifacts");
        std::fs::create_dir_all(artifacts).unwrap();

        let mut report = json!({
            "cases": [],
            "all_pii_processed": true,
            "non_pii_unchanged": true,
            "auditable": true,
        });
        let audit_path = artifacts.join("redaction-audit.jsonl");
        if audit_path.exists() {
            std::fs::remove_file(&audit_path).unwrap();
        }

        for (name, fixture) in [
            ("deep_object", deep_object_fixture()),
            ("object_array", object_array_fixture()),
            ("nested_arrays", nested_arrays_fixture()),
        ] {
            let (mut value, paths, secrets) = fixture;
            let before = value.clone();
            let transform = Redact::new(&RedactConfig {
                paths: paths.clone(),
                audit: AuditConfig {
                    file: Some(audit_path.to_string_lossy().to_string()),
                    log: false,
                    ..AuditConfig::default()
                },
                ..RedactConfig::default()
            })
            .unwrap();
            let outcome = transform.redact_value(&mut value);
            transform.audit_sink().flush();
            let patterns: Vec<PathPattern> = paths.iter().map(|p| parse_path(p).unwrap()).collect();
            let consistency = verify_redaction(&before, &value, &patterns);
            let leaks = scan_secrets(&value, &secrets);
            assert!(leaks.is_empty(), "case {name} leaked PII: {leaks:?}");
            assert!(consistency.consistent);
            report["cases"].as_array_mut().unwrap().push(json!({
                "name": name,
                "pii_locations": outcome.paths.len(),
                "audit_records": outcome.records.len(),
                "consistent": consistency.consistent,
                "fingerprints_match": consistency.fingerprints_match,
                "leaks": leaks.len(),
            }));
        }
        std::fs::write(
            artifacts.join("redaction-acceptance-report.json"),
            serde_json::to_string_pretty(&report).unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn integrates_with_vector_topology() {
        use tokio::sync::mpsc;
        use tokio_stream::wrappers::ReceiverStream;

        use crate::test_util::components::assert_transform_compliance;
        use crate::transforms::test::create_topology;

        Box::pin(assert_transform_compliance(async {
            let config = RedactConfig {
                paths: vec!["user.email".to_string()],
                audit: AuditConfig {
                    enabled: false,
                    ..AuditConfig::default()
                },
                ..RedactConfig::default()
            };

            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let event = Event::from(LogEvent::from(value_from_json(json!({
                "user": {"email": "topo@example.com"},
                "keep": 42
            }))));
            tx.send(event).await.unwrap();

            let received = out.recv().await.expect("one transformed event");
            let encoded = serde_json::to_value(received.as_log().value()).unwrap();
            assert_eq!(encoded["user"]["email"], json!(DEFAULT_REPLACEMENT));
            assert_eq!(encoded["keep"], json!(42));

            drop(tx);
            topology.stop().await;
        }))
        .await;
    }
}
