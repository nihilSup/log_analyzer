import unittest

from log_analyzer.log_analyzer import find_log, LogFile


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
                              '20170630', None)
        self.assertEqual(find_log(files), corerct_log)

    def test_empty_files(self):
        files = []
        with self.assertRaises(Exception):
            find_log(files)

if __name__ == "__main__":
    unittest.main()
