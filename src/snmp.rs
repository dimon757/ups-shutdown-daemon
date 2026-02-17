// snmp.rs — SNMP v1/v2c trap packet parsing
//
// Pure functions only: no state, no I/O.
// Parses raw UDP bytes into a ParsedTrap with the OID and community string.

use anyhow::Result;

// ── Parsed packet ───────────────────────────────────────────────────────────

pub struct ParsedTrap {
    pub oid:       Vec<u64>,
    pub community: String,
}

// ── ASN.1 BER helpers ───────────────────────────────────────────────────────

fn read_asn1_header(data: &[u8], offset: usize) -> Option<(u8, usize, usize)> {
    if offset + 1 >= data.len() { return None; }
    let tag      = data[offset];
    let len_byte = data[offset + 1];
    if len_byte < 0x80 {
        Some((tag, len_byte as usize, 2))
    } else {
        let n = (len_byte & 0x7F) as usize;
        if offset + 1 + n >= data.len() { return None; }
        let mut len = 0usize;
        for i in 0..n { len = (len << 8) | data[offset + 2 + i] as usize; }
        Some((tag, len, 2 + n))
    }
}

fn read_header(data: &[u8], offset: usize, ctx: &str) -> Result<(u8, usize, usize)> {
    read_asn1_header(data, offset)
        .ok_or_else(|| anyhow::anyhow!("Truncated ASN.1 at '{}' offset {}", ctx, offset))
}

fn parse_oid_bytes(bytes: &[u8]) -> Result<Vec<u64>> {
    if bytes.is_empty() { return Ok(vec![]); }
    let mut oid = vec![(bytes[0] / 40) as u64, (bytes[0] % 40) as u64];
    let mut i   = 1;
    while i < bytes.len() {
        let mut val = 0u64;
        loop {
            if i >= bytes.len() { break; }
            let b = bytes[i]; i += 1;
            val = (val << 7) | (b & 0x7F) as u64;
            if b & 0x80 == 0 { break; }
        }
        oid.push(val);
    }
    Ok(oid)
}

// ── Packet parser ───────────────────────────────────────────────────────────

/// Decode a raw UDP payload into an OID and community string.
/// Supports SNMPv2c (tag 0xa7) and SNMPv1 (tag 0xa4).
pub fn parse_snmp_trap(data: &[u8]) -> Result<ParsedTrap> {
    let mut i = 0;
    let (_, _,    h)  = read_header(data, i, "outer SEQUENCE")?; i += h;
    let (_, vlen, vh) = read_header(data, i, "version")?;        i += vh + vlen;
    let (_, clen, ch) = read_header(data, i, "community")?;
    let community = String::from_utf8_lossy(&data[i + ch .. i + ch + clen]).into_owned();
    i += ch + clen;

    if i >= data.len() { anyhow::bail!("Truncated after community"); }
    let pdu_tag = data[i];

    // ── SNMPv2c Trap-PDU (0xa7) ──────────────────────────────────────────
    if pdu_tag == 0xa7 {
        let (_, _, hl) = read_header(data, i, "v2 PDU")?;
        let mut cur    = i + hl;
        for f in ["request-id", "error-status", "error-index"] {
            let (_, l, h) = read_header(data, cur, f)?; cur += h + l;
        }
        let (tag, vbl, h) = read_header(data, cur, "VarBindList")?;
        if tag != 0x30 { anyhow::bail!("Expected SEQUENCE for VarBindList"); }
        cur += h;
        let vbl_end = cur + vbl;
        while cur < vbl_end && cur < data.len() {
            let (tag, vb_len, h) = read_header(data, cur, "VarBind")?;
            if tag != 0x30 { break; }
            cur += h;
            let vb_end = cur + vb_len;
            let (tag, oid_len, h) = read_header(data, cur, "VB OID")?;
            if tag != 0x06 { cur = vb_end; continue; }
            let oid = parse_oid_bytes(&data[cur + h .. cur + h + oid_len])?;
            cur += h + oid_len;
            if oid == [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] {
                let (tag, tl, th) = read_header(data, cur, "trapOID value")?;
                if tag == 0x06 {
                    let trap_oid = parse_oid_bytes(&data[cur + th .. cur + th + tl])?;
                    return Ok(ParsedTrap { oid: trap_oid, community });
                }
            }
            cur = vb_end;
        }
        anyhow::bail!("snmpTrapOID.0 not found");
    }

    // ── SNMPv1 Trap-PDU (0xa4) ───────────────────────────────────────────
    if pdu_tag == 0xa4 {
        let (_, _, hl) = read_header(data, i, "v1 PDU")?;
        let mut cur    = i + hl;

        let (tag, el, eh) = read_header(data, cur, "enterprise")?;
        if tag != 0x06 { anyhow::bail!("Expected OID for enterprise"); }
        let enterprise = parse_oid_bytes(&data[cur + eh .. cur + eh + el])?;
        cur += eh + el;

        // agent-addr: skip header AND 4-byte value
        let (_, al, ah) = read_header(data, cur, "agent-addr")?; cur += ah + al;

        let (_, gl, gh) = read_header(data, cur, "generic-trap")?;
        let gen = if gl > 0 { data[cur + gh] as u64 } else { 0 };
        cur += gh + gl;

        let (_, sl, sh) = read_header(data, cur, "specific-trap")?;
        let spec = if sl > 0 { data[cur + sh] as u64 } else { 0 };

        if gen == 6 {
            let mut full = enterprise;
            full.push(0);
            full.push(spec);
            return Ok(ParsedTrap { oid: full, community });
        }
        return Ok(ParsedTrap { oid: enterprise, community });
    }

    anyhow::bail!("Unsupported PDU tag 0x{:02x}", pdu_tag)
}
