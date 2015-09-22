#!/usr/bin/python

import sys
import requests

from socket import gaierror, gethostbyname
from argparse import ArgumentParser

DEFAULT_WORDLIST = 'list.txt'

LOG_FILE = 'output.txt'

MODE_DIRS = 'm'
MODE_SUB = 's'

def f_header():

    print '''

                   {__      {_____    
                   {__      {__   {__ 
     {____ {__  {__{__      {__    {__
    {__    {__  {__{__ {__  {__    {__
      {___ {__  {__{__   {__{__    {__
        {__{__  {__{__   {__{__   {__ 
    {__ {__  {__{__{__ {__  {_____                                                         


    '''

def error_handler(msg):

    print '[!]', msg
    sys.exit(1)

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
                    default=DEFAULT_WORDLIST,
                    type=str,
                    metavar='<wordlist>',
                    help='Bruteforce useing <wordlist>')

    parser.add_argument('-t','--target',
                    dest='target',
                    required=True,
                    type=str,
                    metavar='<domain>',
                    help='The target domain')

    args = parser.parse_args()

    return {
        'mode' : args.mode,
        'wordlist' : args.wordlist,
        'target' : args.target,
    }

def bruteforce_dirs(configs):

    domain = configs['target']
    input_file = configs['wordlist']
        
    url = domain
    ip_addr = gethostbyname(url)

    print '[*] Checking %s' % url
    response = requests.head('http://%s' % url)
    if response.status_code < 200 or response.status_code >= 400:

        error_handler('Invalid target')

    # get number of lines in file
    num_lines = sum(1 for line in open(input_file))
    
    with open(input_file, 'r') as input_handle, open(LOG_FILE, 'w') as log:
    
        for line_number, line in enumerate(input_handle):
            
            subdomain = line.rstrip()
            url = '%s.%s' % (subdomain, domain)
            try:
                response = requests.head('http://%s' % url)
            except requests.exceptions.ConnectionError:
                continue

            if response.status_code >= 200 and response.status_code < 400:

                ip_addr = gethostbyname(url)
                print "Progress [%d - %d] Response: %d --> Target: %s --> IP: %s" %\
                    (line_number, num_lines, response.status_code, url, ip_addr)
                log.write('%d %s %s\n' %\
                    (response.status_code, url, ip_addr))

def bruteforce_sub(configs):
    
    domain = configs['target']
    input_file = configs['wordlist']
        
    url = domain
    try:
        ip_addr = gethostbyname(url)
    except gaierror:
        error_handler('Invalid target')

    print '[*] Checking %s' % url
    response = requests.head('http://%s' % url)
    if response.status_code < 200 or response.status_code >= 400:
        error_handler('Invalid target')

    # get number of lines in file
    num_lines = sum(1 for line in open(input_file))
    
    with open(input_file, 'r') as input_handle, open(LOG_FILE, 'w') as log:
    
        for line_number, line in enumerate(input_handle):
            
            dirname = line.rstrip()
            url = '%s/%s' % (domain, dirname)
            try:
                response = requests.head('http://%s' % url)
            except requests.exceptions.ConnectionError:
                continue

            if response.status_code >= 200 and response.status_code < 300:

                print "Progress [%d - %d] Response: %d --> Target: %s --> IP: %s" %\
                    (line_number, num_lines, response.status_code, url, ip_addr)
                log.write('%d %s %s\n' %\
                    (response.status_code, url, ip_addr))
    
def main():

    f_header()

    configs = set_configs()
    
    domain = configs['target']
    input_file = configs['wordlist']
    mode = configs['mode']

    if mode == MODE_DIRS:
        bruteforce_dirs(configs)
    else:
        bruteforce_sub(configs)

if __name__ == '__main__':
    main()
