#!/usr/bin/python

# Waldo / Version 0.1.0
# Red|Team|Labs - Top-Hat-Sec
# By: R4v3N & s0lst1ce

import sys
import requests

from socket    import gaierror, gethostbyname
from argparse  import ArgumentParser
from Queue     import Queue
from threading import Thread

__version__  = '0.1.0'

# configs 
MAX_WORKERS  = 4

DEFAULT_SUB_LIST = 'sublist.txt'
DEFAULT_DIR_LIST = 'dirlist.txt'

LOG_FILE  = 'output.txt'
MODE_DIRS = 'd'
MODE_SUB  = 's'

q = Queue(MAX_WORKERS * 2)

# directory enumeration --------------------------------------------------------

def bruteforce_dirs(configs):

    domain = configs['domain']
    input_file = configs['wordlist']
    max_workers = configs['max_workers']
    domain_ip = configs['domain_ip']

    
    # get number of lines in file
    file_len = sum(1 for line in open(input_file))

    for i in xrange(max_workers):
        t = Thread(target=check_dir)
        t.daemon = True
        t.start()

    try:

        with open(input_file, 'r') as input_handle:
            
            for line_number, line in enumerate(input_handle):
                
                relative_path = line.rstrip()
                url = '%s/%s' % (domain, relative_path)
                q.put({
                    'url' : url,
                    'line_number' : line_number,
                    'file_len' : file_len,
                    'domain_ip' : domain_ip,
                })
            q.join()

    except KeyboardInterrupt:
        sys.exit(1)

def check_dir():

    while True:
    
        params = q.get()

        url = params['url']
        line_number = params['line_number']
        file_len = params['file_len']
        ip_addr = params['domain_ip']

        status_code = get_status(url)

        if status_code >= 200 and status_code < 300:

            write_status(url, line_number, file_len, ip_addr, status_code)

        q.task_done()

# subdomain enumeration -------------------------------------------------------

def bruteforce_sub(configs):

    domain = configs['domain']
    input_file = configs['wordlist']
    max_workers = configs['max_workers']


    # get number of lines in file
    file_len = sum(1 for line in open(input_file))

    for i in xrange(max_workers):
        t = Thread(target=check_subdomain)
        t.daemon = True
        t.start()

    try:

        with open(input_file, 'r') as input_handle:
            
            for line_number, line in enumerate(input_handle):
                
                subdomain = line.rstrip()
                url = '%s.%s' % (subdomain, domain)
                q.put({
                    'url' : url,
                    'line_number' : line_number,
                    'file_len' : file_len,
                })
            q.join()
    except KeyboardInterrupt:
        sys.exit(1)

def check_subdomain():

    while True:
    
        params = q.get()

        url = params['url']
        line_number = params['line_number']
        file_len = params['file_len']

        status_code = get_status(url)

        if status_code >= 200 and status_code < 400:

            ip_addr = gethostbyname(url)
            write_status(url, line_number, file_len, ip_addr, status_code)

        q.task_done()

# auxiliary functions ---------------------------------------------------------

def f_header():

    print '''

  _/          _/            _/        _/           
 _/          _/    _/_/_/  _/    _/_/_/    _/_/    
_/    _/    _/  _/    _/  _/  _/    _/  _/    _/   
 _/  _/  _/    _/    _/  _/  _/    _/  _/    _/    
  _/  _/        _/_/_/  _/    _/_/_/    _/_/                                                                

       Red|Team|Labs <> Top-Hat-Sec
           Waldo - Version 1.0
    '''

def error_handler(msg):

    print '[!]', msg
    sys.exit(1)

def get_status(url):

    try:
        response = requests.head('http://%s' % url)
    except requests.exceptions.ConnectionError:
        return -1

    return response.status_code

def write_status(url, line_number, file_len, ip_addr, status_code):

    print "Progress [%d - %d] Response: %d --> Target: %s --> IP: %s" %\
        (line_number, file_len, status_code, url, ip_addr)

def run_initial_check(url):

    try:
        ip_addr = gethostbyname(url)
    except gaierror:
        error_handler('Invalid target')

    print '[*] Checking %s' % url
    response = requests.head('http://%s' % url)
    #https://www.youtube.com/watch?v=3cEQX632D1M
    if response.status_code < 200 or response.status_code >= 400:
        error_handler('Invalid target')

    return ip_addr

def set_configs():

    parser = ArgumentParser()

    parser.add_argument('-m', '--mode',
                    dest='mode',
                    required=True,
                    type=str,
                    metavar='<mode>',
                    choices=['d', 's'],
                    help='Set mode to "s" for subdomains, "d" for directories.')

    parser.add_argument('-w','--wordlist',
                    dest='wordlist',
                    required=False,
                    default=None,
                    type=str,
                    metavar='<wordlist>',
                    help='Bruteforce useing <wordlist>')

    parser.add_argument('-d','--domain',
                    dest='domain',
                    required=True,
                    type=str,
                    metavar='<domain>',
                    help='The target domain')

    parser.add_argument('-t','--threads',
                    dest='max_workers',
                    required=False,
                    default=MAX_WORKERS,
                    type=int,
                    metavar='<threads>',
                    help='Specify the maximum number of threads to use.')

    args = parser.parse_args()

    if args.wordlist is None:
        if args.mode == MODE_DIRS:
            args.wordlist = DEFAULT_DIR_LIST
        else:
            args.wordlist = DEFAULT_SUB_LIST

    return {
        'mode' : args.mode,
        'wordlist' : args.wordlist,
        'domain' : args.domain,
        'max_workers' : args.max_workers,
    }

def main():

    f_header()

    configs = set_configs()

    configs['domain_ip'] = run_initial_check(configs['domain'])

    if configs['mode'] == MODE_DIRS:
        bruteforce_dirs(configs)
    else:
        bruteforce_sub(configs)

if __name__ == '__main__':
    main()
