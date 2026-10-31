import unittest
from unittest.mock import patch

from ical_subscription import parse_calendar, normalize_url, _public_address

PREFIX = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n"
SUFFIX = "END:VCALENDAR\r\n"


def event(*lines):
    return 'BEGIN:VEVENT\r\n' + '\r\n'.join(lines) + '\r\nEND:VEVENT\r\n'


class IcalSubscriptionTests(unittest.TestCase):
    def test_weekly_exdate_override_cancellation_and_stable_ids(self):
        text = PREFIX + event(
            'UID:mechanics-1@example.edu', 'DTSTART;TZID=Europe/Berlin:20261019T080000',
            'DTEND;TZID=Europe/Berlin:20261019T110000', 'SUMMARY:Mechanik',
            'RRULE:FREQ=WEEKLY;COUNT=4', 'EXDATE;TZID=Europe/Berlin:20261026T080000'
        ) + event(
            'UID:mechanics-1@example.edu', 'RECURRENCE-ID;TZID=Europe/Berlin:20261102T080000',
            'DTSTART;TZID=Europe/Berlin:20261103T100000',
            'DTEND;TZID=Europe/Berlin:20261103T120000',
            'SUMMARY:Mechanik \\(verschoben\\)', 'LOCATION:Labor 1'
        ) + event(
            'UID:mechanics-1@example.edu', 'RECURRENCE-ID;TZID=Europe/Berlin:20261109T080000',
            'DTSTART;TZID=Europe/Berlin:20261109T080000',
            'DTEND;TZID=Europe/Berlin:20261109T110000',
            'STATUS:CANCELLED'
        ) + SUFFIX
        values = parse_calendar(text)
        self.assertEqual([(e['date'], e['start']) for e in values],
                         [('2026-10-19','08:00'), ('2026-11-03','10:00')])
        self.assertEqual(values[1]['end'], '12:00')
        self.assertEqual(values[1]['details'], 'Labor 1')
        self.assertEqual([x['id'] for x in values], [x['id'] for x in parse_calendar(text)])

    def test_timezone_utc_conversion_and_folding(self):
        text = PREFIX + event('UID:utc1', 'DTSTART:20261031T090000Z',
                              'DTEND:20261031T103000Z', 'SUMMARY:Werkstoff',
                              'DESCRIPTION:Lange Beschreibung die umgebrochen',
                              ' wurde') + SUFFIX
        rows = parse_calendar(text)
        self.assertEqual((rows[0]['start'], rows[0]['end']), ('10:00','11:30'))
        self.assertIn('umgebrochenwurde', rows[0]['details'])

    def test_dst_is_correct_for_weekly_timetable(self):
        text = PREFIX + event('UID:dst', 'DTSTART;TZID=Europe/Berlin:20261024T100000',
                              'DTEND;TZID=Europe/Berlin:20261024T110000',
                              'RRULE:FREQ=WEEKLY;COUNT=3', 'SUMMARY:Zeitumstellung') + SUFFIX
        rows = parse_calendar(text)
        self.assertEqual([e['start'] for e in rows], ['10:00'] * 3)

    def test_empty_valid_calendar_is_not_a_parse_error(self):
        self.assertEqual(parse_calendar(PREFIX + SUFFIX), [])

    def test_malformed_calendar_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_calendar('not a calendar')
        with self.assertRaises(ValueError):
            parse_calendar(PREFIX + event('DTSTART:20261031T100000', 'SUMMARY:No UID') + SUFFIX)

    def test_normalize_url_secure(self):
        self.assertEqual(normalize_url('webcal://example.org/feed.ics?key=secret'),
                         'https://example.org/feed.ics?key=secret')
        for url in ('http://example.org/calendar', 'https://localhost/x',
                    'https://user:pass@example.org/cal', 'https://example.org:8080/calendar',
                    'file:///etc/passwd', 'https://example.org/a\nb'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                normalize_url(url)

    def test_dns_guard_rejects_private_and_mixed_answers(self):
        def answer(ip):
            return (2, 1, 6, '', (ip, 443))
        with patch('ical_subscription.socket.getaddrinfo', return_value=[answer('127.0.0.1')]):
            with self.assertRaises(ValueError):
                _public_address('example.org')
        with patch('ical_subscription.socket.getaddrinfo', return_value=[answer('8.8.8.8'), answer('10.1.2.3')]):
            with self.assertRaises(ValueError):
                _public_address('example.org')
        with patch('ical_subscription.socket.getaddrinfo', return_value=[answer('8.8.8.8')]):
            self.assertEqual(_public_address('example.org'), '8.8.8.8')


if __name__ == '__main__':
    unittest.main()
