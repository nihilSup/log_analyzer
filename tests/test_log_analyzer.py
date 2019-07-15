import unittest
from datetime import datetime
import re

from log_analyzer.log_analyzer import (find_log, LogFile, build_date,
                                       build_nginx_log_regexp, parse_log,
                                       create_report)


class TestCreateReport(unittest.TestCase):
    def setUp(self):
        self.parsed_log = [
            dict(url='some_url', request_time=0.5),
            dict(url='some_url', request_time=1.5),
            dict(url='some_url', request_time='0.1'),
            dict(url='other_url', request_time='2.1'),
            dict(url='another_url', request_time='0'),
        ]
        self.empty_log = []

    def test_correct_report(self):
        report = create_report(self.parsed_log)
        self.assertIsNotNone(report)
        self.assertEqual(len(report), 3)
        url = [r for r in report if r['url'] == 'some_url'][0]
        self.assertEqual(url['count'], 3)
        self.assertEqual(url['time_sum'], 2.1)
        self.assertEqual(url['count_perc'], 100 * 3 / 5)
        self.assertEqual(url['time_perc'], 100 * 0.5)

    def test_empty_log(self):
        report = create_report(self.empty_log)

    def test_log_size(self):
        size = 2
        report = create_report(self.parsed_log, size)
        self.assertEqual(len(report), size)


class TestParseLog(unittest.TestCase):
    def setUp(self):
        self.pattern = build_nginx_log_regexp()
        self.lines = [
            ('1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] '
             '"GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" '
             '"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" '
             '"-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390\n'),
            ('1.99.174.176 3b81f63526fa8  - [29/Jun/2017:03:50:22 +0300] '
             '"GET /api/1/photogenic_banners/list/?server_name=WIN7RB4 HTTP/1.1" 200 12 "-" '
             '"Python-urllib/2.7" "-" "1498697422-32900793-4708-9752770" "-" 0.133\n'),
            'aaaaaa',
        ]

    def test_multiple_lines(self):
        res = list(parse_log(self.lines, self.pattern))
        self.assertEqual(len(res), 2)

    def test_treshold(self):
        with self.assertRaises(Exception):
            res = list(parse_log(self.lines, self.pattern, treshold=0.7))


class TestBuildNginxLogRegexp(unittest.TestCase):
    def setUp(self):
        self.good_line = (
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] '
            '"GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" '
            '"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" '
            '"-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390\n')
        self.bad_line = (
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] '
            '"GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" '
            '"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" '
            '"-" "1498697422-2190034393-4708-9752759" 0.390\n'
        )
        self.pattern = pattern = build_nginx_log_regexp()

    def test_pattern_match(self):
        res = re.search(self.pattern, self.good_line, re.IGNORECASE)
        self.assertIsNotNone(res)
        res = re.search(self.pattern, self.bad_line, re.IGNORECASE)
        self.assertIsNone(res)

    def test_fields_presence(self):
        res = re.search(self.pattern, self.good_line, re.IGNORECASE)
        res_dct = res.groupdict()
        self.assertTrue(
            all(key in res_dct for key in ['url', 'request_time'])
        )
        print(res_dct['url'], res_dct['request_time'])


class TestFindLog(unittest.TestCase):
    def test_max(self):
        files = [
            'nginx-access-ui.log-20170630',
            'nginx-access-ui.log-20170630.gz',
            'nginx-access-ui.log-20170629',
            'nginx-access-ui.log-20170531',
            'nginx-access-ui.log-20150630',
            'nginx-ui.log-20190630',
            'aaaaa',
            '',
            'nginx-access-ui.log-20190530.bzz',
            'nginx-access-ui.log-390630.bz',
            'nginx-access-ui.log-201907301111.bz'
        ]
        corerct_log = LogFile('nginx-access-ui.log-20170630',
                              build_date('20170630'), None)
        self.assertEqual(find_log(files), corerct_log)

    def test_empty_files(self):
        files = []
        self.assertIsNone(find_log(files))

    def test_empty_matches(self):
        files = [
            'aaa',
            'bbb',
        ]
        self.assertIsNone(find_log(files))


if __name__ == "__main__":
    unittest.main()
