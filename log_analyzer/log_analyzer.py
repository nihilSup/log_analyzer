#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import argparse
import json
import logging
import re
from datetime import datetime
from collections import namedtuple
import gzip
from string import Template

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
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
        # create_report(log_parser(log_file))
    except Exception as e:
        logging.exception('Log proccessing failed', e)
        sys.exit(2)


def parse_args(def_config):
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str)
    args = parser.parse_args()
    if args.config:
        with open(args.config) as json_config:
            new_config = json.load(json_config)
            def_config.update(dict(new_config))


def setup_logging(config):
    LOG_FILENAME = 'log_analyzer.log'
    LOG_DIR = config['LOG_DIR']
    filename = os.path.join(LOG_DIR, LOG_FILENAME) if LOG_DIR else None
    print(filename)
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    logging.basicConfig(filename=filename,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        level=logging.INFO)


LogFile = namedtuple("LogFile", "path, date, ext")


def build_date(string):
    return datetime.strptime(str(string), '%Y%m%d')


def find_log(files):
    """
    Finds earliest log file amongst files.
    log names examples:
        nginx-access-ui.log-20170630
        nginx-access-ui.log-20170630.gz
    """
    lst = []
    for f in files:
        match = re.match(r'nginx-access-ui\.log-(\d{8})(\.gz)?$', f)
        if match:
            lst.append(LogFile(match.group(),
                               build_date(match.group(1)),
                               match.group(2)))
    if not lst:
        raise Exception('No available logs')
    return max(lst, key=lambda l: l.date)
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
        'remote_addr': r'(?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        'remote_user': r'(?P<remote_user>\S+)',
        'http_x_real_ip': r'(?P<http_x_real_ip>\S+)',
        'time_local': r'(?P<time_local>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})',
        'request': r'(((GET|POST) )(?P<url>.+)(http\/1\.1))',  # r'(?P<request>.*?)',
        'status': r'(?P<status>\d{3})',
        'body_bytes_sent': r'(?P<body_bytes_sent>\d+)',
        'http_referer': r'(?P<http_referer>\S+)',
        'http_user_agent': r'(?P<http_user_agent>.+?)',
        'http_x_forwarded_for': r'(?P<http_x_forwarded_for>\S+)',
        'http_X_REQUEST_ID': r'(?P<http_X_REQUEST_ID>(\-)|([\w\d-]+))',
        'http_X_RB_USER': r'(?P<http_X_RB_USER>(\-)|([\w\d]+))',
        'request_time': r'(?P<request_time>\d+\.\d+)',
    }
    if groups:
        _groups.update(groups)

    t = Template(r'$remote_addr $remote_user\s+$http_x_real_ip '
                 r'\[$time_local\] \"$request\" $status $body_bytes_sent '
                 r'\"$http_referer\" \"$http_user_agent\" \"$http_x_forwarded_for\" '
                 r'\"$http_X_REQUEST_ID\" \"$http_X_RB_USER\" $request_time\s*')
    return t.substitute(**_groups)


def parse_log(lines, pattern_builder=build_nginx_log_regexp):
    # TODO: implement
    for line in lines:
        pass

if __name__ == "__main__":
    main()
