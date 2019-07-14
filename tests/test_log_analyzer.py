import unittest
from datetime import datetime
import re

from log_analyzer.log_analyzer import (find_log, LogFile, build_date,
                                       build_nginx_log_regexp, parse_log)


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
    def test_pattern_match(self):
        pattern = build_nginx_log_regexp()
        # pattern = re.compile(pattern_str)
        log_line = ('1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] '
                    '"GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" '
                    '"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" '
                    '"-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390\n')
        res = re.search(pattern, log_line, re.IGNORECASE)
        self.assertIsNotNone(res)
        log_line = ('1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] '
                    '"GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" '
                    '"Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" '
                    '"-" "1498697422-2190034393-4708-9752759" 0.390\n')
        res = re.search(pattern, log_line, re.IGNORECASE)
        self.assertIsNone(res)


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
        with self.assertRaises(Exception):
            find_log(files)

    def test_empty_matches(self):
        files = [
            'aaa',
            'bbb',
        ]
        with self.assertRaises(Exception):
            find_log(files)


if __name__ == "__main__":
    unittest.main()
