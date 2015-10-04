#!/usr/bin/env python2

# Waldo / Version 0.1.2
# Red|Team|Labs - Top-Hat-Sec
# By: R4v3N & s0lst1ce

import sys
import requests
import re
import json
import curses

from socket import gaierror, gethostbyname
from argparse import ArgumentParser
from Queue import Queue
from threading import Thread
from datetime import datetime

__version__ = '0.1.2'

# configs
MAX_WORKERS = 4

DEFAULT_LIST = 'default.txt'

LOG_FILE = 'waldo-output.txt'
MODE_DIRS = 'd'
MODE_SUB = 's'

class OutputThread(Thread):

    def __init__(self, queue, build_subdomain_map=False):

        Thread.__init__(self)
        self.queue = queue
        self.build_subdomain_map = build_subdomain_map

    def run(self):

        while True:

            result = self.queue.get()

            self.write_result(result['line_number'],
                              result['file_len'],
                              result['status_code'],
                              result['url'],
                              result['ip_addr'],
                              result['success'])

            if self.build_subdomain_map:

                self.add_to_subdomain_map(result)

            self.queue.task_done()

    def write_result(self, line_number, file_len, status_code, url, ip_addr, success):

        sys.stdout.write('\r')
        if success:
            print "[ %d ] Target: %s --> IP: %s" %\
                (status_code, url, ip_addr)
            
        sys.stdout.write("Progress [ %d - %d ]" % (line_number, file_len))
        sys.stdout.flush()

        resume_handle.write('%d\n' % line_number)
        output_handle.write('%d %s %s\n' % (status_code, url, ip_addr))

    def add_to_subdomain_map(self, result):

        ip_addr = result['ip_addr']
        url = result['url']
        status_code = '%d' % result['status_code']

        if ip_addr in subdomain_map:
            if status_code in subdomain_map[ip_addr]:
                subdomain_map[ip_addr][status_code].append(url)
            else:
                subdomain_map[ip_addr][status_code] = [url]
        else:
            subdomain_map[ip_addr] = {status_code: [url]}


class WorkerThread(Thread):

    def __init__(self, in_queue, out_queue):

        Thread.__init__(self)
        self.in_queue = in_queue
        self.out_queue = out_queue

    def run(self):

        while True:

            params = self.in_queue.get()

            params['status_code'] = self.get_status(params['url'])

            if self.status_ok(params['status_code']):

                params['ip_addr'] = self.get_ip(params)
                params['success'] = True
            else:
                params['ip_addr'] = None
                params['success'] = False

            self.out_queue.put(params)

            self.in_queue.task_done()

    def get_status(self, url):

        try:
            response = requests.head('http://%s' % url)
        except requests.exceptions.ConnectionError:
            return -1

        return response.status_code


class DirThread(WorkerThread):

    def status_ok(self, status_code):

        if status_code >= 200 and status_code < 300:
            return True
        return False

    def get_ip(self, params):
        return params['domain_ip']


class SubThread(WorkerThread):

    def status_ok(self, status_code):

        if status_code >= 200 and status_code < 400:
            return True
        return False

    def get_ip(self, params):
        return gethostbyname(params['url'])

# auxiliary functions ---------------------------------------------------------


def print_header():

    print '''

  _/          _/            _/        _/
 _/          _/    _/_/_/  _/    _/_/_/    _/_/
_/    _/    _/  _/    _/  _/  _/    _/  _/    _/
 _/  _/  _/    _/    _/  _/  _/    _/  _/    _/
  _/  _/        _/_/_/  _/    _/_/_/    _/_/

       Red|Team|Labs <> Top-Hat-Sec
           Waldo - Version '''+__version__+'''

'''

def print_configs(configs):

    print
    print '[*] Target domain:', configs['domain']
    print '[*] Target IP:    ', configs['domain_ip']
    if configs['mode'] == MODE_DIRS:
        print '[*] Mode:          enumerate directories'
    else:
        print '[*] Mode:          enumerate subdomains'
    print '[*] Wordlist:     ', configs['wordlist']
    print

def error_handler(msg):

    print '[!]', msg
    sys.exit(1)


def run_initial_check(url):

    try:
        ip_addr = gethostbyname(url)
    except gaierror:
        error_handler('Invalid target %s' % url)

    print '[Setup] Checking %s' % url
    response = requests.head('http://%s' % url)
    # https://www.youtube.com/watch?v=3cEQX632D1M
    if response.status_code < 200 or response.status_code >= 400:
        error_handler('Invalid target %s' % url)

    print '[Setup] %s is valid... continuing' % url

    return ip_addr


def gen_logfile_name(domain):

    now = datetime.now()
    return now.strftime('{domain}-%Y-%m-%d-%H-%M-%S.log').format(domain=domain)


def parse_args():

    parser = ArgumentParser()

    parser.add_argument('-m', '--mode',
                        dest='mode',
                        required=True,
                        type=str,
                        metavar='<mode>',
                        choices=['d', 's'],
                        help='Set mode to "s" for subdomains, "d" for dire"\
                        "ctories.')

    parser.add_argument('-w', '--wordlist',
                        dest='wordlist',
                        required=False,
                        default=DEFAULT_LIST,
                        type=str,
                        metavar='<wordlist>',
                        help='Bruteforce useing <wordlist>')

    parser.add_argument('-l', '--log-file',
                        dest='log_file',
                        required=False,
                        default=None,
                        type=str,
                        metavar='<log_file>',
                        help='Log results to <log_file>')

    parser.add_argument('-d', '--domain',
                        dest='domain',
                        required=True,
                        type=str,
                        metavar='<domain>',
                        help='The target domain')

    parser.add_argument('-b', '--build-subdomain-map',
                        dest='build_subdomain_map',
                        action='store_true',
                        required=False,
                        default=False,
                        help='Build a subdomain map')

    parser.add_argument('-t', '--threads',
                        dest='max_workers',
                        required=False,
                        default=MAX_WORKERS,
                        type=int,
                        metavar='<threads>',
                        help='Specify the maximum number of threads to use.')

    args = parser.parse_args()

    return {
        'mode': args.mode,
        'wordlist': args.wordlist,
        'domain': re.sub('http[s]?://', '', args.domain).rstrip('/'),
        'max_workers': args.max_workers,
        'log_file': args.log_file,
        'build_subdomain_map': args.build_subdomain_map,
    }


def set_configs():

    configs = parse_args()
    configs['domain_ip'] = run_initial_check(configs['domain'])

    if configs['mode'] == MODE_DIRS:
        configs['url_builder'] = '%s/%%s' % configs['domain']
        configs['worker_thread'] = DirThread
    else:
        configs['url_builder'] = '%%s.%s' % configs['domain']
        configs['worker_thread'] = SubThread

    if configs['log_file'] is None:
        configs['log_file'] = gen_logfile_name(configs['domain'])

    # get number of lines in wordlist file
    configs['file_len'] = sum(1 for line in open(configs['wordlist']))

    return configs


output_handle = None
resume_handle = None
subdomain_map = {}


def main():

    global output_handle
    global resume_handle

    print_header()
    configs = set_configs()
    print_configs(configs)

    in_queue = Queue(configs['max_workers'] * 2)
    out_queue = Queue()

    output_handle = open(configs['log_file'], 'w')
    resume_handle = open('resume.txt', 'a')

    output_thread = OutputThread(out_queue,
                                 build_subdomain_map=configs['build_subdomain_map'])
    output_thread.daemon = True
    output_thread.start()

    threads = []
    for i in xrange(configs['max_workers']):
        t = configs['worker_thread'](in_queue=in_queue, out_queue=out_queue)
        t.daemon = True
        t.start()
        threads.append(t)

    print_interrupt_message_on_exit = False
    try:
        with open(configs['wordlist']) as input_handle:

            for line_number, line in enumerate(input_handle):


                in_queue.put({
                             'url': configs['url_builder'] % line.strip(),
                             'line_number': line_number,
                             'file_len': configs['file_len'],
                             'domain_ip': configs['domain_ip'],
                             })
            in_queue.join()

    except KeyboardInterrupt:
        print_interrupt_message_on_exit = True

    out_queue.join()
    output_handle.close()
    resume_handle.close()
       
    if print_interrupt_message_on_exit:
        print '\n\n[!] Exiting on user interupt.\n'

    if configs['build_subdomain_map']:
        print json.dumps(subdomain_map, indent=4, sort_keys=True)
    sys.exit(0)

if __name__ == '__main__':
    main()
