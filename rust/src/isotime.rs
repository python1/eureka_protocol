//! Timestamps as the Python daemon writes and reads them.
//!
//! Writing is `datetime.now(timezone.utc).isoformat()`. Reading is
//! `datetime.fromisoformat`, ported from CPython 3.13's C implementation
//! (`_find_isoformat_datetime_separator`, `parse_isoformat_date`,
//! `parse_isoformat_time`, `parse_hh_mm_ss_ff`), because whether a request is
//! refused as stale or as malformed depends on exactly which strings it
//! accepts. A naive timestamp is treated as UTC, as node.py does.

use chrono::{DateTime, Datelike, NaiveDate, Timelike, Utc};

/// The system clock in UTC, read without chrono's `clock` feature (which would link the platform's time-zone libraries).
fn now() -> DateTime<Utc> {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock after 1970");
    DateTime::from_timestamp(since.as_secs() as i64, since.subsec_nanos()).expect("clock in range")
}

/// `datetime.now(timezone.utc).isoformat()`: microseconds only when non-zero.
pub fn now_iso() -> String {
    let now = now();
    let micros = now.nanosecond() / 1000 % 1_000_000;
    let base = now.format("%Y-%m-%dT%H:%M:%S").to_string();
    if micros == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{micros:06}+00:00")
    }
}

pub fn now_micros() -> i128 {
    let now = now();
    now.timestamp() as i128 * 1_000_000 + (now.nanosecond() / 1000 % 1_000_000) as i128
}

/// Seconds between now and `timestamp`, or None if Python could not parse it.
pub fn age_seconds(timestamp: &str) -> Option<f64> {
    let sent = parse_fromisoformat(timestamp)?;
    Some((now_micros() - sent) as f64 / 1e6)
}

/// The instant `datetime.fromisoformat(s)` names, in microseconds since the
/// Unix epoch, or None where Python raises.
pub fn parse_fromisoformat(s: &str) -> Option<i128> {
    // _sanitize_isoformat_str: every valid string is at least 7 characters.
    if s.chars().count() < 7 {
        return None;
    }
    let b = s.as_bytes();
    let len = b.len();
    let sep = find_separator(b)?;
    let (year, month, day) = parse_date(b, sep)?;
    let (mut hour, mut minute, mut second, mut micro, mut tz) = (0, 0, 0, 0, None);
    if len > sep {
        let start = sep + 1;
        let (h, m, sec, us, offset) = parse_time(b, start, len)?;
        (hour, minute, second, micro, tz) = (h, m, sec, us, offset);
    }
    // new_datetime's range checks.
    if !(1..=9999).contains(&year) || hour > 23 || minute > 59 || second > 59 || micro > 999_999 {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(year as i32, month as u32, day as u32)?;
    let offset_micros = match tz {
        None => 0,
        Some(us) => {
            // timezone() requires -24h < offset < 24h.
            if us.abs() >= 86_400_000_000 {
                return None;
            }
            us
        }
    };
    let days = date.num_days_from_ce() as i128 - 719_163; // 1970-01-01
    let local = ((days * 86_400 + hour as i128 * 3600 + minute as i128 * 60 + second as i128) * 1_000_000) + micro as i128;
    Some(local - offset_micros)
}

/// Reading past the end yields NUL, as it does in CPython's C string.
fn at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

fn find_separator(b: &[u8]) -> Option<usize> {
    let len = b.len();
    if len == 7 {
        return Some(7);
    }
    if at(b, 4) == b'-' {
        if at(b, 5) == b'W' {
            if len < 8 {
                return None;
            }
            if len > 8 && at(b, 8) == b'-' {
                if len == 9 {
                    return None;
                }
                if len > 10 && at(b, 10).is_ascii_digit() {
                    return Some(8);
                }
                return Some(10);
            }
            return Some(8);
        }
        return Some(10);
    }
    if at(b, 4) == b'W' {
        let mut idx = 7;
        while idx < len && at(b, idx).is_ascii_digit() {
            idx += 1;
        }
        if idx < 9 {
            return Some(idx);
        }
        return Some(if idx % 2 == 0 { 7 } else { 8 });
    }
    Some(8)
}

fn digits(b: &[u8], p: &mut usize, n: usize) -> Option<i64> {
    let mut v = 0i64;
    for _ in 0..n {
        let d = at(b, *p).wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        v = v * 10 + d as i64;
        *p += 1;
    }
    Some(v)
}

fn parse_date(b: &[u8], len: usize) -> Option<(i64, i64, i64)> {
    let mut p = 0;
    let year = digits(b, &mut p, 4)?;
    let uses_separator = at(b, p) == b'-';
    if uses_separator {
        p += 1;
    }
    if at(b, p) == b'W' {
        p += 1;
        let week = digits(b, &mut p, 2)?;
        let weekday = if p < len {
            if uses_separator {
                if at(b, p) != b'-' {
                    return None;
                }
                p += 1;
            }
            digits(b, &mut p, 1)?
        } else {
            1
        };
        if !(1..=7).contains(&weekday) || !(1..=53).contains(&week) {
            return None;
        }
        let weekday = chrono::Weekday::try_from(weekday as u8 - 1).ok()?;
        let date = NaiveDate::from_isoywd_opt(year as i32, week as u32, weekday)?;
        return Some((date.year() as i64, date.month() as i64, date.day() as i64));
    }
    let month = digits(b, &mut p, 2)?;
    if uses_separator {
        if at(b, p) != b'-' {
            return None;
        }
        p += 1;
    }
    let day = digits(b, &mut p, 2)?;
    Some((year, month, day))
}

/// parse_hh_mm_ss_ff over b[start..end]. Ok((h, m, s, us, not_at_end)).
fn hh_mm_ss_ff(b: &[u8], start: usize, end: usize) -> Result<(i64, i64, i64, i64, bool), ()> {
    let mut vals = [0i64; 3];
    let mut p = start;
    let mut has_separator = true;
    let mut fraction = false;
    for i in 0..3 {
        vals[i] = digits(b, &mut p, 2).ok_or(())?;
        let c = at(b, p);
        p += 1;
        if i == 0 {
            has_separator = c == b':';
        }
        if p >= end {
            return Ok((vals[0], vals[1], vals[2], 0, c != 0));
        } else if has_separator && c == b':' {
            if i == 2 {
                return Err(());
            }
            continue;
        } else if c == b'.' || c == b',' {
            if i < 2 {
                return Err(());
            }
            fraction = true;
            break;
        } else if !has_separator {
            p -= 1;
        } else {
            return Err(());
        }
    }
    let _ = fraction;
    let to_parse = (end - p).min(6);
    let mut micro = digits(b, &mut p, to_parse).ok_or(())?;
    if to_parse < 6 {
        micro *= [100_000, 10_000, 1_000, 100, 10][to_parse - 1];
    }
    while at(b, p).is_ascii_digit() {
        p += 1;
    }
    Ok((vals[0], vals[1], vals[2], micro, at(b, p) != 0))
}

type Time = (i64, i64, i64, i64, Option<i128>);

fn parse_time(b: &[u8], start: usize, end: usize) -> Option<Time> {
    let mut tz = start;
    loop {
        if matches!(at(b, tz), b'Z' | b'+' | b'-') {
            break;
        }
        tz += 1;
        if tz >= end {
            break;
        }
    }
    let (h, m, s, us, more) = hh_mm_ss_ff(b, start, tz).ok()?;
    if tz >= end {
        return if more { None } else { Some((h, m, s, us, None)) };
    }
    if at(b, tz) == b'Z' {
        return if at(b, tz + 1) != 0 { None } else { Some((h, m, s, us, Some(0))) };
    }
    let sign: i128 = if at(b, tz) == b'-' { -1 } else { 1 };
    let (th, tm, ts, tus, tmore) = hh_mm_ss_ff(b, tz + 1, end).ok()?;
    if tmore {
        return None;
    }
    let offset = sign * ((th as i128 * 3600 + tm as i128 * 60 + ts as i128) * 1_000_000 + tus as i128);
    Some((h, m, s, us, Some(offset)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso(s: &str) -> Option<String> {
        parse_fromisoformat(s).map(|us| {
            let secs = us.div_euclid(1_000_000) as i64;
            let micros = us.rem_euclid(1_000_000);
            let t = chrono::DateTime::from_timestamp(secs, 0).unwrap();
            format!("{}.{:06}", t.format("%Y-%m-%dT%H:%M:%S"), micros)
        })
    }

    #[test]
    fn accepts_what_python_accepts() {
        // Expected values are Python 3.13's, converted to UTC.
        let cases = [
            ("2026-10-31T12:00:00Z", Some("2026-10-31T12:00:00.000000")),
            ("2026-10-31T12:00:00.123Z", Some("2026-10-31T12:00:00.123000")),
            ("2026-10-31 12:00", Some("2026-10-31T12:00:00.000000")),
            ("20261031T120000", Some("2026-10-31T12:00:00.000000")),
            ("2026-10-31", Some("2026-10-31T00:00:00.000000")),
            ("2026-10-31T12", Some("2026-10-31T12:00:00.000000")),
            ("2026-10-31T12:00:00.1234567+00:00", Some("2026-10-31T12:00:00.123456")),
            ("2026-10-31X12:00:00", Some("2026-10-31T12:00:00.000000")),
            ("2026-10-31T12:00:00+0530", Some("2026-10-31T06:30:00.000000")),
            ("2026-10-31T12:00:00,5", Some("2026-10-31T12:00:00.500000")),
            ("2026-W44-6", Some("2026-10-31T00:00:00.000000")),
            ("2026-10-31T24:00:00", None),
            ("2026-10-31T1200", Some("2026-10-31T12:00:00.000000")),
            ("2026-10-31T12:00:00+05", Some("2026-10-31T07:00:00.000000")),
            ("2026-10-31T12:00:00 ", None),
            ("2026-10-31T12:00:00.Z", Some("2026-10-31T12:00:00.000000")),
            ("2026-10-31T12:00:60", None),
            ("2026-02-30", None),
            ("hello world", None),
            ("2026-10-31T12:00:00+24:00", None),
        ];
        for (s, want) in cases {
            assert_eq!(iso(s).as_deref(), want, "{s}");
        }
    }

    #[test]
    fn now_round_trips() {
        let t = now_iso();
        assert!(t.ends_with("+00:00"));
        assert!(age_seconds(&t).unwrap().abs() < 1.0);
    }
}
