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
from functools import partial

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "APP_LOG_FILE": "./app_logs/log_analyzer.log",
    "REPORT_TEMPLATE": "./report.html",
}


def main():
    try:
        parse_args(config)
        setup_logging(config)
    except Exception as e:
        logging.exception('App init failed', e)
        sys.exit(1)
    logging.info('App started')
    try:
        log_dir = config['LOG_DIR']
        files = [f for f in os.listdir(log_dir)]
        log_file = find_log(files)
        if not log_file:
            logging.info('No available logs to process. Exiting')
            sys.exit(0)
        logging.info(f'Latest log is \n{log_file.path}')
        report_dt = log_file.date.strftime('%Y.%m.%d')
        report_name = 'report-{}.html'.format(report_dt)
        report_file_path = os.path.join(config['REPORT_DIR'], report_name)
        if os.path.isfile(report_file_path):
            logging.info(f'Report file \n{report_file_path}\nalready exists')
            sys.exit(0)
        log_data = read_log_file(log_file, log_dir)
        logging.info('Starting log parsing.')
        pattern = build_nginx_log_regexp()
        parsed_log = parse_log(log_data, pattern)
        report = create_report(parsed_log, config['REPORT_SIZE'])
        logging.info('Report created, writing to disk')
        with open(config['REPORT_TEMPLATE']) as tmplt_file:
            tmplt = tmplt_file.read()
        save_report(report, report_file_path, tmplt)
        logging.info('Finshed processing')
    except Exception as e:
        logging.exception('Log processing failed', e)
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
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    logging.basicConfig(filename=log_file_path,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        level=logging.INFO)


LogFile = namedtuple("LogFile", "path, date, ext")


def find_log(log_files):
    """
    Finds latest log file amongst files.
    log names examples:
        nginx-access-ui.log-20170630
        nginx-access-ui.log-20170630.gz
    """
    pattern = r'nginx-access-ui\.log-(?P<date>\d{8})(?P<ext>\.gz)?$'
    matches = []
    for f in log_files:
        match = re.match(pattern, f)
        if match:
            try:
                dt = datetime.strptime(match.group('date'), '%Y%m%d')
            except ValueError as ve:
                logging.exception(ve)
                continue
            log_file = LogFile(match.group(),
                               dt,
                               match.group('ext'))
            matches.append(log_file)
    if not matches:
        return None
    return max(matches, key=lambda l: l.date)


def read_log_file(log_file, dir_path):
    file_path = os.path.join(dir_path, log_file.path)
    openers = {
        None: open,
        '.gz': partial(gzip.open, mode='rt', encoding='UTF-8'),
    }
    with openers[log_file.ext](file_path) as f:
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
        'request':              r'(((GET|POST) )(?P<url>.+)(http\/1\.1))',
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
    # TODO: add as argument with default
    t = Template(r'$remote_addr $remote_user\s+$http_x_real_ip '
                 r'\[$time_local\] \"$request\" $status $body_bytes_sent '
                 r'\"$http_referer\" \"$http_user_agent\" '
                 r'\"$http_x_forwarded_for\" \"$http_X_REQUEST_ID\" '
                 r'\"$http_X_RB_USER\" $request_time\s*')
    return t.substitute(**_groups)


def parse_log(log_lines, pattern, treshold=0.6):
    """
    Transforms every line to pattern's groupdict if line matchs pattern,
    else skips line. Raises exception if conversion rate is lower then treshold
    """
    p = re.compile(pattern, re.IGNORECASE)
    tot_ln_count = 0
    corr_ln_count = 0
    for line in log_lines:
        tot_ln_count += 1
        res = re.search(p, line)
        if res:
            corr_ln_count += 1
            yield res.groupdict()
        if tot_ln_count % 100000 == 0:
            logging.info(f'Parsed {tot_ln_count} lines')
    parsed_rate = corr_ln_count / tot_ln_count
    logging.info(f'Parsed rate is {parsed_rate:.2f}')
    if parsed_rate < treshold:
        raise Exception(f'Parsed rate lower than {treshold:.2f}')


def create_report(log_parsed_data, size=None, prec=3):
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
            'time_sum': round(sum(reqs), prec),
            'time_max': round(max(reqs), prec),
            'time_med': round(median(reqs), prec),
        }
        url_stats.update({
            'count_perc': round(100 * url_stats['count'] / tot_count, prec),
            'time_perc': round(100 * url_stats['time_sum'] / tot_req_time, prec),
            'time_avg': round(url_stats['time_sum'] / len(reqs), prec),
        })
        report_data.append(url_stats)
    res = sorted(report_data, key=lambda dct: dct['time_sum'], reverse=True)
    return res[:size]


def save_report(report, path, tmplt):
    report = tmplt.replace('$table_json', json.dumps(report))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as report_file:
        report_file.write(report)


if __name__ == "__main__":
    main()
