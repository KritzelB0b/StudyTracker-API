"""Authenticated iCalendar feed reader: pinned public HTTPS fetch and bounded recurrence expansion.

The feed URL is accepted per request, never logged or persisted by this module.
"""
from datetime import date, datetime, time, timedelta, timezone
from hashlib import sha256
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urljoin, urlsplit, urlunsplit
from zoneinfo import ZoneInfo

from dateutil.rrule import rrulestr

LOCAL_TZ = ZoneInfo('Europe/Berlin')
MAX_BYTES = 1_000_000
MAX_EVENTS = 2500


def normalize_url(raw):
    if not isinstance(raw, str) or len(raw) > 2048:
        raise ValueError('Ungültiger iCal-Link.')
    value = raw.strip()
    if value.lower().startswith('webcal://'):
        value = 'https://' + value[9:]
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        raise ValueError('Ungültiger iCal-Port.') from None
    if (parts.scheme != 'https' or not parts.hostname or parts.username or
            parts.password or port not in (None, 443) or
            len(parts.hostname) > 253 or any(x.isspace() for x in value)):
        raise ValueError('Nur öffentliche HTTPS- oder webcal-Links ohne Zugangsdaten im URL-Benutzernamen sind erlaubt.')
    # Block IPv4/IPv6 literals, including IPv4-integer aliases: feeds should use DNS hosts.
    host = parts.hostname
    if not all(c.isalnum() or c in '.-' for c in host) or '.' not in host:
        raise ValueError('Der Kalender benötigt einen öffentlichen Hostnamen.')
    return urlunsplit(('https', parts.netloc, parts.path or '/', parts.query, ''))


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, port=443, timeout=8, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _public_address(host):
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError('Kalender-Host konnte nicht aufgelöst werden.') from None
    ips = [ipaddress.ip_address(entry[4][0]) for entry in answers]
    # Reject the entire hostname if even one DNS answer is private/reserved.
    if not ips or any(not ip.is_global for ip in ips):
        raise ValueError('Private oder reservierte Kalender-Server sind nicht erlaubt.')
    return str(ips[0])


def fetch_calendar(raw):
    url = normalize_url(raw)
    for _ in range(4):
        target = urlsplit(url)
        address = _public_address(target.hostname)
        connection = PinnedHTTPS(target.hostname, address)
        try:
            path = target.path or '/'
            if target.query:
                path += '?' + target.query
            connection.request('GET', path, headers={
                'Accept': 'text/calendar, text/plain;q=0.9, */*;q=0.5',
                'Accept-Encoding': 'identity',
                'User-Agent': 'StudyTracker-iCal/1.0',
                'Host': target.hostname,
            })
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if not location:
                    raise ValueError('Kalender-Weiterleitung ohne Ziel.')
                url = normalize_url(urljoin(url, location))
                continue
            if response.status != 200:
                raise ValueError('Kalender-Server antwortet nicht erfolgreich (HTTP %s).' % response.status)
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError('Kalender ist größer als 1 MB.')
            text = data.decode('utf-8-sig', errors='replace')
            if 'BEGIN:VCALENDAR' not in text.upper():
                raise ValueError('Der Link liefert keinen iCalendar-Kalender.')
            return text
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise ValueError('Kalender konnte über HTTPS nicht abgerufen werden.') from exc
        finally:
            connection.close()
    raise ValueError('Zu viele Kalender-Weiterleitungen.')


def _unescape(value):
    return (value.replace(r'\N', '\n').replace(r'\n', '\n')
            .replace(r'\,', ',').replace(r'\;', ';').replace(r'\\', '\\'))


def _properties(text):
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('Kalender ist zu groß.')
    unfolded = []
    for line in text.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
        if line.startswith((' ', '\t')) and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    events, current, depth = [], None, 0
    for line in unfolded:
        upper = line.upper()
        if upper == 'BEGIN:VEVENT':
            if current is not None:
                raise ValueError('Verschachtelte VEVENT-Einträge werden nicht unterstützt.')
            current, depth = {}, 0
        elif upper == 'END:VEVENT':
            if current is not None:
                events.append(current)
            current = None
        elif current is not None:
            if upper.startswith('BEGIN:'):
                depth += 1
            elif upper.startswith('END:'):
                depth = max(0, depth - 1)
            elif depth == 0 and ':' in line:
                left, value = line.split(':', 1)
                sections = left.split(';')
                key = sections[0].upper()
                params = dict(s.split('=', 1) for s in sections[1:] if '=' in s)
                current.setdefault(key, []).append((params, value))
    if 'BEGIN:VCALENDAR' not in text.upper() or 'END:VCALENDAR' not in text.upper():
        raise ValueError('Unvollständiger iCalendar-Kalender.')
    return events


def _prop(component, name):
    values = component.get(name, [])
    return values[0] if values else ({}, '')


def _datetime(value, params=None):
    params = params or {}
    text = value.strip()
    if len(text) == 8 and text.isdigit():
        return datetime.strptime(text, '%Y%m%d').replace(tzinfo=LOCAL_TZ)
    if text.endswith('Z'):
        return datetime.strptime(text, '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    fmt = '%Y%m%dT%H%M%S' if len(text) == 15 else '%Y%m%dT%H%M'
    tz = params.get('TZID', '').strip('"')
    if tz.startswith('/'):
        tz = tz.lstrip('/')
    zone = ZoneInfo(tz) if tz else LOCAL_TZ
    return datetime.strptime(text, fmt).replace(tzinfo=zone)


def _key(dt):
    return dt.astimezone(timezone.utc).isoformat()


def _multiple(component, name):
    for params, value in component.get(name, []):
        for part in value.split(','):
            if part.strip():
                yield _datetime(part, params)


def parse_calendar(text, start='2026-10-01', end='2030-03-31'):
    low = datetime.combine(date.fromisoformat(start), time.min, LOCAL_TZ)
    high = datetime.combine(date.fromisoformat(end) + timedelta(days=1), time.min, LOCAL_TZ)
    if high <= low or high-low > timedelta(days=365 * 5):
        raise ValueError('Ungültiger Kalenderzeitraum.')
    raw = _properties(text)
    if len(raw) > 3000:
        raise ValueError('Zu viele Kalendereinträge.')
    masters, detached = [], {}
    for item in raw:
        uid = _unescape(_prop(item, 'UID')[1]).strip()
        if not uid or len(uid) > 512:
            raise ValueError('Kalender enthält einen Termin ohne gültige UID.')
        _, recurrence = _prop(item, 'RECURRENCE-ID')
        if recurrence:
            rec_dt = _datetime(recurrence, _prop(item, 'RECURRENCE-ID')[0])
            detached[uid, _key(rec_dt)] = item
        else:
            masters.append((uid, item))

    result = {}
    seen_overrides = set()

    def insert(uid, occurrence_key, item, start_dt=None):
        if _prop(item, 'STATUS')[1].strip().upper() == 'CANCELLED':
            return
        params, raw_start = _prop(item, 'DTSTART')
        if not raw_start:
            raise ValueError('Kalendertermin ohne DTSTART.')
        actual = _datetime(raw_start, params) if start_dt is None else start_dt
        params_end, raw_end = _prop(item, 'DTEND')
        if raw_end:
            duration = _datetime(raw_end, params_end) - _datetime(raw_start, params)
        elif _prop(item, 'DURATION')[1]:
            # Duration fields are uncommon in timetable feeds. Reject to avoid misleading times.
            raise ValueError('Ein Kalendertermin benutzt DURATION statt DTEND.')
        else:
            duration = timedelta(hours=1)
        if duration <= timedelta(0) or duration > timedelta(days=1):
            raise ValueError('Kalendertermin mit ungültiger Dauer.')
        if not (low <= actual.astimezone(LOCAL_TZ) < high):
            return
        end_dt = actual + duration
        local_start = actual.astimezone(LOCAL_TZ)
        local_end = end_dt.astimezone(LOCAL_TZ)
        name = _unescape(_prop(item, 'SUMMARY')[1]).strip()[:130] or 'Veranstaltung'
        room = _unescape(_prop(item, 'LOCATION')[1]).strip()[:150]
        desc = _unescape(_prop(item, 'DESCRIPTION')[1]).strip()[:160]
        detail = ' · '.join(x for x in (room, desc) if x)[:280]
        event_id = sha256((uid + '\0' + occurrence_key).encode('utf-8')).hexdigest()[:32]
        result[event_id] = {
            'id': event_id, 'date': local_start.strftime('%Y-%m-%d'),
            'start': local_start.strftime('%H:%M'), 'end': local_end.strftime('%H:%M'),
            'name': name, 'details': detail
        }
        if len(result) > MAX_EVENTS:
            raise ValueError('Zu viele Kalendertermine im gewählten Zeitraum.')

    for uid, master in masters:
        params, value = _prop(master, 'DTSTART')
        if not value:
            raise ValueError('Kalendertermin ohne DTSTART.')
        first = _datetime(value, params)
        occurrences = [first]
        _, rule = _prop(master, 'RRULE')
        if _prop(master, 'EXRULE')[1]:
            raise ValueError('EXRULE wird nicht unterstützt.')
        if rule:
            try:
                expanded = rrulestr(rule, dtstart=first).between(low, high, inc=True)
            except (ValueError, TypeError) as exc:
                raise ValueError('Wiederholungsregel konnte nicht gelesen werden.') from exc
            occurrences = expanded
        occurrences += list(_multiple(master, 'RDATE'))
        exclusions = {_key(value) for value in _multiple(master, 'EXDATE')}
        for occurrence in occurrences:
            stamp = _key(occurrence)
            if stamp in exclusions:
                continue
            override = detached.get((uid, stamp))
            if override:
                seen_overrides.add((uid, stamp))
                insert(uid, stamp, override)
            else:
                insert(uid, stamp, master, occurrence)

    # Some feeds contain only detached exceptions or move events into the range.
    for (uid, stamp), override in detached.items():
        if (uid, stamp) not in seen_overrides:
            insert(uid, stamp, override)
    return sorted(result.values(), key=lambda x: (x['date'], x['start'], x['id']))
