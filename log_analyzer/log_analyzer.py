#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import argparse
import json
import logging
import re
from datetime import datetime
from collections import namedtuple, defaultdict
import gzip
from string import Template
from statistics import median

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "APP_LOG_FILE": "./log/log_analyzer.log",
    "REPORT_TEMPLATE": "./report.html",
}


def main():
    try:
        parse_args(config)
        setup_logging(config)
    except Exception as e:
        logging.exception('App init failed', e)
        sys.exit(1)
    logging.info('Started')
    try:
        files = os.listdir(config['LOG_DIR'])
        log_file = find_log(files)
        logging.info(f'Latest log is \n{log_file}')
        report_name = build_report_name(log_file.date)
        report_file_path = os.path.join(config['REPORT_DIR'], report_name)
        if os.path.isfile(report_file_path):
            logging.info(f'Report file \n{report_file_path}\nalready exists')
            sys.exit(0)
        log_data = read_log_file(log_file, config['LOG_DIR'])
        logging.info('Starting log parsing.')
        pattern = build_nginx_log_regexp()
        parsed_log = parse_log(log_data, pattern)
        report = create_report(parsed_log, config['REPORT_SIZE'])
        logging.info('Report created, writing to disk')
        save_report(report, report_file_path, config['REPORT_TEMPLATE'])
    except Exception as e:
        logging.exception('Log proccessing failed', e)
        sys.exit(2)


def parse_args(def_config):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, help='path to config file',
                        default='./config.json')
    args = parser.parse_args()
    if args.config:
        with open(args.config) as json_config:
            new_config = json.load(json_config)
            def_config.update(dict(new_config))


def setup_logging(config):
    log_file_path = config.get("APP_LOG_FILE", None)
    if log_file_path:
        os.makedirs(log_file_path, exist_ok=True)
    logging.basicConfig(filename=log_file_path,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        level=logging.INFO)


LogFile = namedtuple("LogFile", "path, date, ext")


def build_date(string):
    return datetime.strptime(str(string), '%Y%m%d')


def find_log(files):
    """
    Finds latest log file amongst files.
    log names examples:
        nginx-access-ui.log-20170630
        nginx-access-ui.log-20170630.gz
    """
    pattern = r'nginx-access-ui\.log-(?P<date>\d{8})(?P<ext>\.gz)?$'
    lst = []
    for f in files:
        match = re.match(pattern, f)
        if match:
            lst.append(LogFile(match.group(),
                               build_date(match.group('date')),
                               match.group('ext')))
    if not lst:
        raise Exception('No available logs')
    return max(lst, key=lambda l: l.date)
    # lexigraphical check
    # return max([f for f in files
    #             if re.match(r'nginx-access-ui\.log-(\d{8})(\.gz)?', f)])


def build_report_name(date):
    return 'report-{}.html'.format(date.strftime('%Y.%m.%d'))


def read_log_file(log_file, dir_path):
    file_path = os.path.join(dir_path, log_file.path)
    openers = {
        '': open,
        '.gz': gzip.open,
    }
    with openers[log_file.ext]() as f:
        for line in f:
            yield line


def build_nginx_log_regexp(groups=None):
    """
    Arguments:
        groups: dict-like object with keys corresponding to nginx log vars.
                There is dict with defaults inside. Argument dict will override
                defaults
    returns:
        str: regexp string
    """
    _groups = {
        'remote_addr':          r'(?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        'remote_user':          r'(?P<remote_user>\S+)',
        'http_x_real_ip':       r'(?P<http_x_real_ip>\S+)',
        'time_local':           r'(?P<time_local>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})',
        'request':              r'(((GET|POST) )(?P<url>.+)(http\/1\.1))',  # r'(?P<request>.*?)',
        'status':               r'(?P<status>\d{3})',
        'body_bytes_sent':      r'(?P<body_bytes_sent>\d+)',
        'http_referer':         r'(?P<http_referer>\S+)',
        'http_user_agent':      r'(?P<http_user_agent>.+?)',
        'http_x_forwarded_for': r'(?P<http_x_forwarded_for>\S+)',
        'http_X_REQUEST_ID':    r'(?P<http_X_REQUEST_ID>(\-)|([\w\d-]+))',
        'http_X_RB_USER':       r'(?P<http_X_RB_USER>(\-)|([\w\d]+))',
        'request_time':         r'(?P<request_time>\d+\.\d+)',
    }
    if groups:
        _groups.update(groups)

    t = Template(r'$remote_addr $remote_user\s+$http_x_real_ip '
                 r'\[$time_local\] \"$request\" $status $body_bytes_sent '
                 r'\"$http_referer\" \"$http_user_agent\" '
                 r'\"$http_x_forwarded_for\" \"$http_X_REQUEST_ID\" '
                 r'\"$http_X_RB_USER\" $request_time\s*')
    return t.substitute(**_groups)


def parse_log(log_lines, pattern, treshold=0.6):
    p = re.compile(pattern, re.IGNORECASE)
    tot_ln_count = 0
    corr_ln_count = 0
    for line in log_lines:
        tot_ln_count += 1
        res = re.search(p, line)
        if res:
            corr_ln_count += 1
            yield res.groupdict()
    parsed_rate = corr_ln_count / tot_ln_count
    logging.info(f'Parsed rate is {parsed_rate}')
    if parsed_rate < treshold:
        raise Exception(f'Parsed rate lower than {treshold}')


def create_report(log_parsed_data, size=None):
    if size:
        size = int(size)
    urls_reqs = defaultdict(list)
    tot_count, tot_req_time = 0, 0.0
    for data in log_parsed_data:
        req_time = float(data['request_time'])
        tot_count += 1
        tot_req_time += req_time
        urls_reqs[data['url']].append(req_time)
    report_data = []
    for url, reqs in urls_reqs.items():
        url_stats = {
            'url': url,
            'count': len(reqs),
            'time_sum': sum(reqs),
            'time_max': max(reqs),
            'time_med': median(reqs),
        }
        url_stats.update({
            'count_perc': round(100 * url_stats['count'] / tot_count, 3),
            'time_perc': round(100 * url_stats['time_sum'] / tot_req_time, 3),
            'time_avg': round(url_stats['time_sum'] / len(reqs), 3),
        })
        report_data.append(url_stats)
    res = sorted(report_data, key=lambda dct: dct['time_sum'], reverse=True)
    return res[:size]


def save_report(report, path, path_to_template):
    # TODO: Implement
    pass

if __name__ == "__main__":
    main()
