//! A minimal D-Bus client: enough to talk to systemd over the system bus
//! (method calls, replies, signals) without libdbus, sd-bus or an async
//! runtime.
//!
//! * transport: `unix:path=` and `unix:abstract=` addresses;
//! * authentication: `EXTERNAL` (the peer credentials of the socket);
//! * wire format: little-endian marshalling, both endiannesses when reading;
//! * types: every basic type, arrays, dictionaries, structs and variants;
//!   file descriptors are not supported (never negotiated).
//!
//! The connection is blocking and owned by one thread (the systemd sensor).

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub const SYSTEM_BUS_DEFAULT: &str = "unix:path=/run/dbus/system_bus_socket";
/// Spec limit is 128 MiB; nothing we talk to comes close.
const MAX_MESSAGE: usize = 64 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    MethodCall = 1,
    MethodReturn = 2,
    Error = 3,
    Signal = 4,
}

/// A marshalled value. Arrays carry their element signature so that empty
/// arrays can be written; dictionaries are arrays of [`Value::Entry`].
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Byte(u8),
    Bool(bool),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    Double(f64),
    Str(String),
    Path(String),
    Sig(String),
    Array(String, Vec<Value>),
    Struct(Vec<Value>),
    Entry(Box<Value>, Box<Value>),
    Variant(Box<Value>),
}

impl Value {
    pub fn str(s: impl Into<String>) -> Self {
        Value::Str(s.into())
    }

    /// Array of strings (`as`).
    pub fn strings<S: AsRef<str>>(v: &[S]) -> Self {
        Value::Array("s".into(), v.iter().map(|s| Value::Str(s.as_ref().to_owned())).collect())
    }

    pub fn signature(&self) -> String {
        match self {
            Value::Byte(_) => "y".into(),
            Value::Bool(_) => "b".into(),
            Value::I16(_) => "n".into(),
            Value::U16(_) => "q".into(),
            Value::I32(_) => "i".into(),
            Value::U32(_) => "u".into(),
            Value::I64(_) => "x".into(),
            Value::U64(_) => "t".into(),
            Value::Double(_) => "d".into(),
            Value::Str(_) => "s".into(),
            Value::Path(_) => "o".into(),
            Value::Sig(_) => "g".into(),
            Value::Array(t, _) => format!("a{t}"),
            Value::Struct(v) => format!("({})", v.iter().map(Value::signature).collect::<String>()),
            Value::Entry(k, v) => format!("{{{}{}}}", k.signature(), v.signature()),
            Value::Variant(_) => "v".into(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) | Value::Path(s) | Value::Sig(s) => Some(s),
            Value::Variant(v) => v.as_str(),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Value::U32(v) => Some(*v),
            Value::Variant(v) => v.as_u32(),
            _ => None,
        }
    }

    pub fn items(&self) -> &[Value] {
        match self {
            Value::Array(_, v) | Value::Struct(v) => v,
            Value::Variant(v) => v.items(),
            _ => &[],
        }
    }

    /// Look up `key` in an `a{s…}` dictionary.
    pub fn dict_get(&self, key: &str) -> Option<&Value> {
        self.items().iter().find_map(|e| match e {
            Value::Entry(k, v) if k.as_str() == Some(key) => Some(&**v),
            _ => None,
        })
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn alignment(t: u8) -> usize {
    match t {
        b'y' | b'g' | b'v' => 1,
        b'n' | b'q' => 2,
        b'b' | b'i' | b'u' | b's' | b'o' | b'a' | b'h' => 4,
        b'x' | b't' | b'd' | b'(' | b'{' => 8,
        _ => 1,
    }
}

/// Split the first complete type off a signature.
fn split_type(sig: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let Some(&c) = sig.first() else { return Err(bad("empty signature")) };
    match c {
        b'a' => {
            let (_, rest) = split_type(&sig[1..])?;
            let n = sig.len() - rest.len();
            Ok((&sig[..n], rest))
        }
        b'(' | b'{' => {
            let close = if c == b'(' { b')' } else { b'}' };
            let mut rest = &sig[1..];
            let mut fields = 0;
            while rest.first().is_some_and(|&x| x != close) {
                rest = split_type(rest)?.1;
                fields += 1;
            }
            if rest.is_empty() {
                return Err(bad("unterminated container in signature"));
            }
            // An empty struct has no wire size: `a()` made the array loop
            // push empty values for ever without reading a byte — unbounded
            // memory from a 23-byte message (found by the dbus fuzz target).
            // The specification forbids it, and a dict entry has exactly two
            // fields.
            if fields == 0 || (c == b'{' && fields != 2) {
                return Err(bad("struct without fields or malformed dict entry in signature"));
            }
            let n = sig.len() - rest.len() + 1;
            Ok((&sig[..n], &sig[n..]))
        }
        b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g' | b'v' | b'h' => {
            Ok((&sig[..1], &sig[1..]))
        }
        _ => Err(bad(format!("unsupported type code {:?}", c as char))),
    }
}

/// All complete types of a signature.
fn split_all(mut sig: &[u8]) -> io::Result<Vec<&[u8]>> {
    let mut v = Vec::new();
    while !sig.is_empty() {
        let (t, rest) = split_type(sig)?;
        v.push(t);
        sig = rest;
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// writer
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn pad(&mut self, n: usize) {
        while !self.buf.len().is_multiple_of(n) {
            self.buf.push(0);
        }
    }

    fn u32(&mut self, v: u32) {
        self.pad(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn string(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }

    fn sig(&mut self, s: &str) -> io::Result<()> {
        if s.len() > 255 {
            return Err(bad("signature too long"));
        }
        self.buf.push(s.len() as u8);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    fn value(&mut self, t: &[u8], v: &Value) -> io::Result<()> {
        let mismatch = || bad(format!("value {v:?} does not match signature {}", String::from_utf8_lossy(t)));
        match (t[0], v) {
            (b'y', Value::Byte(x)) => self.buf.push(*x),
            (b'b', Value::Bool(x)) => self.u32(u32::from(*x)),
            (b'n', Value::I16(x)) => {
                self.pad(2);
                self.buf.extend_from_slice(&x.to_le_bytes());
            }
            (b'q', Value::U16(x)) => {
                self.pad(2);
                self.buf.extend_from_slice(&x.to_le_bytes());
            }
            (b'i', Value::I32(x)) => self.u32(*x as u32),
            (b'u', Value::U32(x)) => self.u32(*x),
            (b'x', Value::I64(x)) => {
                self.pad(8);
                self.buf.extend_from_slice(&x.to_le_bytes());
            }
            (b't', Value::U64(x)) => {
                self.pad(8);
                self.buf.extend_from_slice(&x.to_le_bytes());
            }
            (b'd', Value::Double(x)) => {
                self.pad(8);
                self.buf.extend_from_slice(&x.to_le_bytes());
            }
            (b's', Value::Str(s)) | (b'o', Value::Path(s)) => self.string(s),
            (b'g', Value::Sig(s)) => self.sig(s)?,
            (b'v', Value::Variant(inner)) => {
                let s = inner.signature();
                self.sig(&s)?;
                self.value(s.as_bytes(), inner)?;
            }
            (b'a', Value::Array(et, items)) => {
                if et.as_bytes() != &t[1..] {
                    return Err(mismatch());
                }
                self.u32(0);
                let len_at = self.buf.len() - 4;
                self.pad(alignment(t[1]));
                let start = self.buf.len();
                for it in items {
                    self.value(&t[1..], it)?;
                }
                let n = (self.buf.len() - start) as u32;
                self.buf[len_at..len_at + 4].copy_from_slice(&n.to_le_bytes());
            }
            (b'(', Value::Struct(items)) => {
                self.pad(8);
                let types = split_all(&t[1..t.len() - 1])?;
                if types.len() != items.len() {
                    return Err(mismatch());
                }
                for (ty, it) in types.iter().zip(items) {
                    self.value(ty, it)?;
                }
            }
            (b'{', Value::Entry(k, val)) => {
                self.pad(8);
                let types = split_all(&t[1..t.len() - 1])?;
                if types.len() != 2 {
                    return Err(mismatch());
                }
                self.value(types[0], k)?;
                self.value(types[1], val)?;
            }
            _ => return Err(mismatch()),
        }
        Ok(())
    }
}

/// Marshal `values` with `signature` (a message body, which starts 8-aligned).
pub fn marshal(signature: &str, values: &[Value]) -> io::Result<Vec<u8>> {
    let types = split_all(signature.as_bytes())?;
    if types.len() != values.len() {
        return Err(bad(format!("signature {signature} has {} types, got {} values", types.len(), values.len())));
    }
    let mut w = Writer::default();
    for (t, v) in types.iter().zip(values) {
        w.value(t, v)?;
    }
    Ok(w.buf)
}

// ---------------------------------------------------------------------------
// reader
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    big: bool,
    depth: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], big: bool) -> Self {
        Self { buf, pos: 0, big, depth: 0 }
    }

    fn align(&mut self, n: usize) -> io::Result<()> {
        let p = self.pos.next_multiple_of(n);
        if p > self.buf.len() {
            return Err(bad("truncated (padding)"));
        }
        self.pos = p;
        Ok(())
    }

    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.buf.len()).ok_or_else(|| bad("truncated"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn fixed<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        self.align(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        if self.big {
            a.reverse();
        }
        Ok(a)
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.fixed::<4>()?))
    }

    fn string(&mut self) -> io::Result<String> {
        let n = self.u32()? as usize;
        let s = self.take(n)?;
        if self.take(1)? != [0] {
            return Err(bad("string not NUL-terminated"));
        }
        String::from_utf8(s.to_vec()).map_err(|_| bad("string is not UTF-8"))
    }

    fn sig(&mut self) -> io::Result<String> {
        let n = self.take(1)?[0] as usize;
        let s = self.take(n)?;
        self.take(1)?;
        String::from_utf8(s.to_vec()).map_err(|_| bad("bad signature"))
    }

    fn value(&mut self, t: &[u8]) -> io::Result<Value> {
        if self.depth > 64 {
            return Err(bad("nesting too deep"));
        }
        Ok(match t[0] {
            b'y' => Value::Byte(self.take(1)?[0]),
            b'b' => Value::Bool(self.u32()? != 0),
            b'n' => Value::I16(i16::from_le_bytes(self.fixed::<2>()?)),
            b'q' => Value::U16(u16::from_le_bytes(self.fixed::<2>()?)),
            b'i' => Value::I32(self.u32()? as i32),
            b'u' | b'h' => Value::U32(self.u32()?),
            b'x' => Value::I64(i64::from_le_bytes(self.fixed::<8>()?)),
            b't' => Value::U64(u64::from_le_bytes(self.fixed::<8>()?)),
            b'd' => Value::Double(f64::from_le_bytes(self.fixed::<8>()?)),
            b's' => Value::Str(self.string()?),
            b'o' => Value::Path(self.string()?),
            b'g' => Value::Sig(self.sig()?),
            b'v' => {
                let s = self.sig()?;
                let (inner, rest) = split_type(s.as_bytes())?;
                if !rest.is_empty() {
                    return Err(bad("variant with more than one type"));
                }
                self.depth += 1;
                let v = self.value(inner)?;
                self.depth -= 1;
                Value::Variant(Box::new(v))
            }
            b'a' => {
                let n = self.u32()? as usize;
                self.align(alignment(t[1]))?;
                let end =
                    self.pos.checked_add(n).filter(|e| *e <= self.buf.len()).ok_or_else(|| bad("array too long"))?;
                let et = &t[1..];
                let mut items = Vec::new();
                self.depth += 1;
                while self.pos < end {
                    let before = self.pos;
                    items.push(self.value(et)?);
                    // every element type takes at least one byte; this keeps
                    // the loop bounded by the array's length whatever comes
                    if self.pos == before {
                        return Err(bad("array element of zero size"));
                    }
                }
                self.depth -= 1;
                if self.pos != end {
                    return Err(bad("array length mismatch"));
                }
                Value::Array(String::from_utf8_lossy(et).into_owned(), items)
            }
            b'(' | b'{' => {
                self.align(8)?;
                let types = split_all(&t[1..t.len() - 1])?;
                self.depth += 1;
                let mut items = types.iter().map(|ty| self.value(ty)).collect::<io::Result<Vec<_>>>()?;
                self.depth -= 1;
                if t[0] == b'{' {
                    if items.len() != 2 {
                        return Err(bad("dict entry must have two fields"));
                    }
                    let v = items.pop().expect("two");
                    let k = items.pop().expect("two");
                    Value::Entry(Box::new(k), Box::new(v))
                } else {
                    Value::Struct(items)
                }
            }
            c => return Err(bad(format!("unsupported type code {:?}", c as char))),
        })
    }
}

/// Unmarshal a message body.
pub fn unmarshal(signature: &str, body: &[u8], big_endian: bool) -> io::Result<Vec<Value>> {
    let mut r = Reader::new(body, big_endian);
    split_all(signature.as_bytes())?.into_iter().map(|t| r.value(t)).collect()
}

// ---------------------------------------------------------------------------
// messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub kind: MsgType,
    pub flags: u8,
    pub serial: u32,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub error_name: Option<String>,
    pub reply_serial: Option<u32>,
    pub destination: Option<String>,
    pub sender: Option<String>,
    pub signature: String,
    pub body: Vec<u8>,
    pub big_endian: bool,
}

impl Message {
    fn new(kind: MsgType) -> Self {
        Self {
            kind,
            flags: 0,
            serial: 0,
            path: None,
            interface: None,
            member: None,
            error_name: None,
            reply_serial: None,
            destination: None,
            sender: None,
            signature: String::new(),
            body: Vec::new(),
            big_endian: false,
        }
    }

    pub fn method_call(destination: &str, path: &str, interface: &str, member: &str) -> Self {
        let mut m = Self::new(MsgType::MethodCall);
        m.destination = Some(destination.into());
        m.path = Some(path.into());
        m.interface = Some(interface.into());
        m.member = Some(member.into());
        m
    }

    pub fn signal(path: &str, interface: &str, member: &str) -> Self {
        let mut m = Self::new(MsgType::Signal);
        m.path = Some(path.into());
        m.interface = Some(interface.into());
        m.member = Some(member.into());
        m
    }

    pub fn method_return(to: &Message) -> Self {
        let mut m = Self::new(MsgType::MethodReturn);
        m.reply_serial = Some(to.serial);
        m.destination = to.sender.clone();
        m
    }

    pub fn error(to: &Message, name: &str, text: &str) -> Self {
        let mut m = Self::new(MsgType::Error);
        m.reply_serial = Some(to.serial);
        m.destination = to.sender.clone();
        m.error_name = Some(name.into());
        m.signature = "s".into();
        m.body = marshal("s", &[Value::str(text)]).expect("static signature");
        m
    }

    pub fn with_body(mut self, signature: &str, values: &[Value]) -> io::Result<Self> {
        self.body = marshal(signature, values)?;
        self.signature = signature.into();
        Ok(self)
    }

    pub fn args(&self) -> io::Result<Vec<Value>> {
        unmarshal(&self.signature, &self.body, self.big_endian)
    }

    pub fn is_signal(&self, interface: &str, member: &str) -> bool {
        self.kind == MsgType::Signal
            && self.interface.as_deref() == Some(interface)
            && self.member.as_deref() == Some(member)
    }

    /// Wire encoding with `serial`.
    pub fn encode(&self, serial: u32) -> io::Result<Vec<u8>> {
        let mut fields: Vec<Value> = Vec::new();
        let mut field =
            |code: u8, v: Value| fields.push(Value::Struct(vec![Value::Byte(code), Value::Variant(Box::new(v))]));
        if let Some(p) = &self.path {
            field(1, Value::Path(p.clone()));
        }
        if let Some(i) = &self.interface {
            field(2, Value::str(i.clone()));
        }
        if let Some(m) = &self.member {
            field(3, Value::str(m.clone()));
        }
        if let Some(e) = &self.error_name {
            field(4, Value::str(e.clone()));
        }
        if let Some(r) = self.reply_serial {
            field(5, Value::U32(r));
        }
        if let Some(d) = &self.destination {
            field(6, Value::str(d.clone()));
        }
        if let Some(s) = &self.sender {
            field(7, Value::str(s.clone()));
        }
        if !self.signature.is_empty() {
            field(8, Value::Sig(self.signature.clone()));
        }
        let mut w = Writer::default();
        w.buf.extend_from_slice(&[b'l', self.kind as u8, self.flags, 1]);
        w.u32(self.body.len() as u32);
        w.u32(serial);
        w.value(b"a(yv)", &Value::Array("(yv)".into(), fields))?;
        w.pad(8);
        w.buf.extend_from_slice(&self.body);
        Ok(w.buf)
    }

    /// Total length of the message starting with this 16-byte prefix.
    pub fn wire_len(prefix: &[u8; 16]) -> io::Result<usize> {
        let big = match prefix[0] {
            b'l' => false,
            b'B' => true,
            _ => return Err(bad("bad endianness marker")),
        };
        let rd = |o: usize| {
            let b: [u8; 4] = prefix[o..o + 4].try_into().expect("4 bytes");
            if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
        };
        let body = rd(4) as usize;
        let fields = rd(12) as usize;
        let total = (16 + fields).next_multiple_of(8) + body;
        if total > MAX_MESSAGE {
            return Err(bad("message too large"));
        }
        Ok(total)
    }

    pub fn decode(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < 16 {
            return Err(bad("short message"));
        }
        let big = buf[0] == b'B';
        let mut r = Reader::new(buf, big);
        let hdr = r.take(4)?;
        let kind = match hdr[1] {
            1 => MsgType::MethodCall,
            2 => MsgType::MethodReturn,
            3 => MsgType::Error,
            4 => MsgType::Signal,
            t => return Err(bad(format!("unknown message type {t}"))),
        };
        let mut m = Self::new(kind);
        m.flags = hdr[2];
        m.big_endian = big;
        let body_len = r.u32()? as usize;
        m.serial = r.u32()?;
        let fields = r.value(b"a(yv)")?;
        for f in fields.items() {
            let it = f.items();
            let (Some(Value::Byte(code)), Some(v)) = (it.first(), it.get(1)) else { continue };
            match code {
                1 => m.path = v.as_str().map(str::to_owned),
                2 => m.interface = v.as_str().map(str::to_owned),
                3 => m.member = v.as_str().map(str::to_owned),
                4 => m.error_name = v.as_str().map(str::to_owned),
                5 => m.reply_serial = v.as_u32(),
                6 => m.destination = v.as_str().map(str::to_owned),
                7 => m.sender = v.as_str().map(str::to_owned),
                8 => m.signature = v.as_str().unwrap_or_default().to_owned(),
                _ => {}
            }
        }
        r.align(8)?;
        m.body = r.take(body_len)?.to_vec();
        Ok(m)
    }
}

// ---------------------------------------------------------------------------
// connection
// ---------------------------------------------------------------------------

pub struct Connection {
    sock: UnixStream,
    serial: u32,
    rbuf: Vec<u8>,
    queue: VecDeque<Message>,
    /// Our name on a bus (`:1.42`); `None` on a peer-to-peer connection.
    pub unique_name: Option<String>,
}

fn connect_one(addr: &str) -> io::Result<UnixStream> {
    let (transport, params) = addr.split_once(':').ok_or_else(|| bad(format!("bad D-Bus address {addr:?}")))?;
    if transport != "unix" {
        return Err(io::Error::new(io::ErrorKind::Unsupported, format!("D-Bus transport {transport:?}")));
    }
    for kv in params.split(',') {
        match kv.split_once('=') {
            Some(("path", p)) => return UnixStream::connect(unescape_address(p)),
            Some(("abstract", name)) => {
                use std::os::linux::net::SocketAddrExt;
                let a = std::os::unix::net::SocketAddr::from_abstract_name(unescape_address(name).as_bytes())?;
                return UnixStream::connect_addr(&a);
            }
            _ => {}
        }
    }
    Err(bad(format!("D-Bus address without path: {addr:?}")))
}

fn hex_byte(b: Option<&[u8]>) -> Option<u8> {
    u8::from_str_radix(std::str::from_utf8(b?).ok()?, 16).ok()
}

/// `%xx` escapes of D-Bus addresses.
fn unescape_address(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = hex_byte(b.get(i + 1..i + 3))
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Connection {
    /// Connect and authenticate (no `Hello`: see [`Self::hello`]).
    pub fn connect(address: &str) -> io::Result<Self> {
        let mut last = bad("empty D-Bus address");
        for a in address.split(';').filter(|a| !a.is_empty()) {
            match connect_one(a) {
                Ok(sock) => {
                    let mut c = Self { sock, serial: 0, rbuf: Vec::new(), queue: VecDeque::new(), unique_name: None };
                    c.auth()?;
                    return Ok(c);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// The system bus, registered (`Hello`).
    pub fn system_bus() -> io::Result<Self> {
        let addr = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").unwrap_or_else(|_| SYSTEM_BUS_DEFAULT.into());
        let mut c = Self::connect(&addr)?;
        c.hello()?;
        Ok(c)
    }

    fn auth(&mut self) -> io::Result<()> {
        self.sock.set_read_timeout(Some(Duration::from_secs(5)))?;
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() }.to_string();
        let hex: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
        self.sock.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())?;
        let line = self.read_line()?;
        if !line.starts_with("OK ") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("D-Bus authentication refused: {line}"),
            ));
        }
        self.sock.write_all(b"BEGIN\r\n")?;
        Ok(())
    }

    fn read_line(&mut self) -> io::Result<String> {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        while !line.ends_with(b"\r\n") {
            if self.sock.read(&mut b)? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "D-Bus peer closed during authentication"));
            }
            line.push(b[0]);
            if line.len() > 4096 {
                return Err(bad("authentication line too long"));
            }
        }
        line.truncate(line.len() - 2);
        Ok(String::from_utf8_lossy(&line).into_owned())
    }

    /// Register on a bus (`org.freedesktop.DBus.Hello`).
    pub fn hello(&mut self) -> io::Result<String> {
        let r = self.call(
            Message::method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello"),
            Duration::from_secs(5),
        )?;
        let name = r.args()?.first().and_then(Value::as_str).map(str::to_owned).ok_or_else(|| bad("Hello: no name"))?;
        self.unique_name = Some(name.clone());
        Ok(name)
    }

    /// Ask the bus to route matching signals to us.
    pub fn add_match(&mut self, rule: &str) -> io::Result<()> {
        let m =
            Message::method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "AddMatch")
                .with_body("s", &[Value::str(rule)])?;
        self.call(m, Duration::from_secs(5)).map(drop)
    }

    pub fn send(&mut self, m: &Message) -> io::Result<u32> {
        self.serial = self.serial.wrapping_add(1).max(1);
        let wire = m.encode(self.serial)?;
        self.sock.write_all(&wire)?;
        Ok(self.serial)
    }

    /// Send a method call and wait for its reply; other messages that
    /// arrive meanwhile are queued for [`Self::recv`]. D-Bus errors become
    /// `io::Error`s carrying the error name and text.
    pub fn call(&mut self, m: Message, timeout: Duration) -> io::Result<Message> {
        let serial = self.send(&m)?;
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, format!("no reply to {:?}", m.member)));
            }
            let Some(r) = self.read_message(left)? else { continue };
            if r.reply_serial == Some(serial) && matches!(r.kind, MsgType::MethodReturn | MsgType::Error) {
                if r.kind == MsgType::Error {
                    let text = r.args().ok().and_then(|a| a.first().and_then(Value::as_str).map(str::to_owned));
                    return Err(io::Error::other(format!(
                        "{}: {}",
                        r.error_name.as_deref().unwrap_or("D-Bus error"),
                        text.unwrap_or_default()
                    )));
                }
                return Ok(r);
            }
            if self.queue.len() < 4096 {
                self.queue.push_back(r);
            }
        }
    }

    /// The next incoming message (signal, call, unmatched reply), or `None`
    /// after `timeout`.
    pub fn recv(&mut self, timeout: Duration) -> io::Result<Option<Message>> {
        if let Some(m) = self.queue.pop_front() {
            return Ok(Some(m));
        }
        self.read_message(timeout)
    }

    fn read_message(&mut self, timeout: Duration) -> io::Result<Option<Message>> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.rbuf.len() >= 16 {
                let prefix: [u8; 16] = self.rbuf[..16].try_into().expect("16 bytes");
                let n = Message::wire_len(&prefix)?;
                if self.rbuf.len() >= n {
                    let m = Message::decode(&self.rbuf[..n]);
                    self.rbuf.drain(..n);
                    return m.map(Some);
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            self.sock.set_read_timeout(Some(left.max(Duration::from_millis(1))))?;
            let mut chunk = [0u8; 16 << 10];
            match self.sock.read(&mut chunk) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "D-Bus connection closed")),
                Ok(n) => self.rbuf.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// systemd's object-path escaping of unit names (`nginx.service` →
/// `nginx_2eservice`): every byte outside `[A-Za-z0-9]` becomes `_xx`.
pub fn escape_path_component(s: &str) -> String {
    if s.is_empty() {
        return "_".into();
    }
    let mut o = String::with_capacity(s.len() * 2);
    for (i, b) in s.bytes().enumerate() {
        if b.is_ascii_alphanumeric() && !(i == 0 && b.is_ascii_digit()) {
            o.push(b as char);
        } else {
            o.push_str(&format!("_{b:02x}"));
        }
    }
    o
}

pub fn unescape_path_component(s: &str) -> String {
    if s == "_" {
        return String::new();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'_'
            && let Some(v) = hex_byte(b.get(i + 1..i + 3))
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Found by the dbus fuzz target: `a()` (an array of empty structs) read
    /// no bytes per element and grew without bound — 23 bytes ran a process
    /// out of memory. Empty structs and malformed dict entries are refused,
    /// and an array element must consume input.
    #[test]
    fn empty_structs_are_refused_instead_of_looping() {
        let body = [3u8, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3];
        assert!(unmarshal("a()", &body, false).is_err());
        assert!(unmarshal("a{s}", &body, false).is_err());
        assert!(unmarshal("a{sss}", &body, false).is_err());
        assert!(unmarshal("v", b"\x03a()\x00\x03\x00\x00\x00", false).is_err());
        let ok = marshal("a{sv}", &[Value::Array("{sv}".into(), vec![])]).unwrap();
        assert_eq!(unmarshal("a{sv}", &ok, false).unwrap().len(), 1);
    }

    #[test]
    fn marshal_roundtrip_of_nested_types() {
        let units = Value::Array(
            "(ssssssouso)".into(),
            vec![Value::Struct(vec![
                Value::str("nginx.service"),
                Value::str("A high performance web server"),
                Value::str("loaded"),
                Value::str("failed"),
                Value::str("failed"),
                Value::str(""),
                Value::Path("/org/freedesktop/systemd1/unit/nginx_2eservice".into()),
                Value::U32(0),
                Value::str(""),
                Value::Path("/".into()),
            ])],
        );
        let props = Value::Array(
            "{sv}".into(),
            vec![
                Value::Entry(
                    Box::new(Value::str("ActiveState")),
                    Box::new(Value::Variant(Box::new(Value::str("failed")))),
                ),
                Value::Entry(Box::new(Value::str("NRestarts")), Box::new(Value::Variant(Box::new(Value::U32(3))))),
                Value::Entry(Box::new(Value::str("Ts")), Box::new(Value::Variant(Box::new(Value::U64(1 << 40))))),
            ],
        );
        let vals = vec![
            Value::Byte(7),
            units,
            props,
            Value::strings::<&str>(&[]),
            Value::Bool(true),
            Value::I16(-2),
            Value::Double(1.5),
        ];
        let sig: String = vals.iter().map(Value::signature).collect();
        assert_eq!(sig, "ya(ssssssouso)a{sv}asbnd");
        let wire = marshal(&sig, &vals).unwrap();
        assert_eq!(unmarshal(&sig, &wire, false).unwrap(), vals);
        assert_eq!(vals[2].dict_get("ActiveState").and_then(Value::as_str), Some("failed"));
        assert_eq!(vals[2].dict_get("NRestarts").and_then(Value::as_u32), Some(3));
        assert!(marshal("s", &[Value::U32(1)]).is_err());
        assert!(unmarshal("s", &wire[..3], false).is_err());
    }

    #[test]
    fn message_encoding_matches_the_spec() {
        // Hello as sent by dbus-send (serial 1), byte for byte.
        let m = Message::method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello");
        let w = m.encode(1).unwrap();
        assert_eq!(&w[..4], b"l\x01\x00\x01");
        assert_eq!(u32::from_le_bytes(w[4..8].try_into().unwrap()), 0, "empty body");
        assert_eq!(w.len() % 8, 0);
        let prefix: [u8; 16] = w[..16].try_into().unwrap();
        assert_eq!(Message::wire_len(&prefix).unwrap(), w.len());
        let back = Message::decode(&w).unwrap();
        assert_eq!(back.member.as_deref(), Some("Hello"));
        assert_eq!(back.destination.as_deref(), Some("org.freedesktop.DBus"));
        assert_eq!(back.serial, 1);

        let sig = Message::signal(
            "/org/freedesktop/systemd1/unit/a_2eservice",
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
        )
        .with_body(
            "sa{sv}as",
            &[
                Value::str("org.freedesktop.systemd1.Unit"),
                Value::Array(
                    "{sv}".into(),
                    vec![Value::Entry(
                        Box::new(Value::str("ActiveState")),
                        Box::new(Value::Variant(Box::new(Value::str("failed")))),
                    )],
                ),
                Value::strings::<&str>(&[]),
            ],
        )
        .unwrap();
        let back = Message::decode(&sig.encode(9).unwrap()).unwrap();
        assert!(back.is_signal("org.freedesktop.DBus.Properties", "PropertiesChanged"));
        assert_eq!(back.args().unwrap()[1].dict_get("ActiveState").and_then(Value::as_str), Some("failed"));
    }

    #[test]
    fn big_endian_messages_are_readable() {
        // Hand-built big-endian signal with body "s" = "hi".
        let mut w: Vec<u8> = vec![b'B', 4, 0, 1];
        w.extend_from_slice(&7u32.to_be_bytes()); // body: u32 len(2) + "hi\0" = 7
        w.extend_from_slice(&5u32.to_be_bytes());
        // fields: (3,'s',"M") and (8,'g',"s")
        let mut f = Vec::new();
        f.extend_from_slice(&[3, 1, b's', 0]);
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(b"M\0");
        while !f.len().is_multiple_of(8) {
            f.push(0);
        }
        f.extend_from_slice(&[8, 1, b'g', 0, 1, b's', 0]);
        w.extend_from_slice(&(f.len() as u32).to_be_bytes());
        w.extend_from_slice(&f);
        while !w.len().is_multiple_of(8) {
            w.push(0);
        }
        w.extend_from_slice(&2u32.to_be_bytes());
        w.extend_from_slice(b"hi\0");
        let m = Message::decode(&w).unwrap();
        assert_eq!(m.member.as_deref(), Some("M"));
        assert_eq!(m.args().unwrap(), vec![Value::str("hi")]);
    }

    #[test]
    fn unit_path_escaping() {
        for u in ["nginx.service", "php8.3-fpm.service", "getty@tty1.service", "2fast.timer", "a_b.mount"] {
            let e = escape_path_component(u);
            assert!(e.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'), "{e}");
            assert_eq!(unescape_path_component(&e), u);
        }
        assert_eq!(escape_path_component("nginx.service"), "nginx_2eservice");
        assert_eq!(unescape_path_component("php8_2e3_2dfpm_2eservice"), "php8.3-fpm.service");
        assert_eq!(unescape_address("/run/my%20bus"), "/run/my bus");
    }
}
