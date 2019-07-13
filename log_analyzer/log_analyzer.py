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
    files = os.listdir(config['LOG_DIR'])
    log = find_log(files)


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
            lst.append(LogFile(match.group(), match.group(1), match.group(2)))
    if not lst:
        raise Exception('No available logs')
    return max(lst, key=lambda l: datetime.strptime(l.date, '%Y%m%d'))
    # return max([f for f in files
    #             if re.match(r'nginx-access-ui\.log-(\d{8})(\.gz)?', f)])


if __name__ == "__main__":
    main()
