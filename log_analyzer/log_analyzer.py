#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import argparse

import json
import logging

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


# some


if __name__ == "__main__":
    main()
