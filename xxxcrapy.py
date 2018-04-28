#!/usr/bin/env python
#Based on xsscrapy

import argparse
from scrapy.cmdline import execute
from xsscrapy.spiders.xss_spider import XSSspider
import sys

__author__ = 'Dan McInerney, demon'
__license__ = 'BSD'
__version__ = '1.0'
__email__ = 'danhmcinerney@gmail.com, d4wner@gmail.com'

def get_args():
    parser = argparse.ArgumentParser(description=__doc__,
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-u', '--url', help="URL to scan; -u http://example.com")
    parser.add_argument('-l', '--login', help="Login name; -l danmcinerney")
    parser.add_argument('-p', '--password', help="Password; -p pa$$w0rd")
    parser.add_argument('-c', '--connections', default='30', help="Set the max number of simultaneous connections allowed, default=30")
    parser.add_argument('-r', '--ratelimit', default='0', help="Rate in requests per minute, default=0")
    parser.add_argument('--basic', help="Use HTTP Basic Auth to login", action="store_true")
    parser.add_argument('-k', '--cookie',help="Cookie key; --cookie SessionID=afgh3193e9103bca9318031bcdf")
    args = parser.parse_args()
    return args

def logo():
    print '''
__  ____  ____  _____ _ __ __ _ _ __  _   _ 
\ \/ /\ \/ /\ \/ / __| '__/ _` | '_ \| | | |
 >  <  >  <  >  < (__| | | (_| | |_) | |_| |
/_/\_\/_/\_\/_/\_\___|_|  \__,_| .__/ \__, |
                               | |     __/ |
                               |_|    |___/  V1.0

    '''
	
def main():
    logo()
    args = get_args()
    rate = args.ratelimit
    if rate not in [None, '0']:
        rate = str(60 / float(rate))
    try:
        cookie_key = args.cookie.split('=',1)[0] if args.cookie else None
        cookie_value = ''.join(args.cookie.split('=',1)[1:]) if args.cookie else None
        execute(['scrapy', 'crawl', 'xsscrapy',
                 '-a', 'url=%s' % args.url, '-a', 'user=%s' % args.login, '-a',
                 'pw=%s' % args.password, '-a', 'basic=%s' % args.basic,
                 '-a', 'cookie_key=%s' % cookie_key, '-a', 'cookie_value=%s' % cookie_value,
                 '-s', 'CONCURRENT_REQUESTS=%s' % args.connections,
                 '-s', 'DOWNLOAD_DELAY=%s' % rate])
    except KeyboardInterrupt:
        sys.exit()

main()
