#!/usr/bin/env python
import os
import sys
import yara
import platform
import hashlib
import validators
from dulwich import porcelain
from configparser import SafeConfigParser
import argparse
import json

not_win = platform.system() != 'Windows'
if(not_win):
    import syslog
LOG_ERR = syslog.LOG_ERR if not_win else 0
LOG_ALERT = syslog.LOG_ALERT if not_win else 0


# config file must be in the same directory
CONF_FILE = 'config.ini'


def clone_rules(r_path, l_path):
    try:
        # redirect output/err to devnull
        f = open(os.devnull, 'wb')
        if(validators.url(r_path)):
            repo = porcelain.clone(r_path, l_path, errstream=f)
            return True
        else:
            return False
    except:
        sys_log(str(sys.exc_info()[1]), LOG_ERR)


def update_rules(r_path, l_path):
    try:
        f = open(os.devnull, 'wb')
        if(os.path.isdir(l_path) and validators.url(r_path)):
            porcelain.pull(l_path, r_path, b'refs/heads/master', errstream=f)
            return True
        else:
            return False
    except:
        sys_log(str(sys.exc_info()[1]), LOG_ERR)


def rest_log(endpoint, payload):
    import requests
    try:
        requests.post(endpoint, json=(payload))
    except:
        sys_log(str(sys.exc_info()[1]), LOG_ERR)


def sys_log(msg, level):
    if(platform.system() != 'Windows'):
        syslog.syslog(level, msg)
    else:
        return False


def init_rules(path):
    rules = []
    if os.path.isdir(path):
        for root, dirs, filenames in os.walk(path):
            for name in filenames:
                try:
                    if not name.startswith('.') and (name.endswith('yar') or name.endswith('yara')):
                        file_path = os.path.join(root, name)
                        rules.append(yara.compile(filepath = file_path, includes=True))
                except:
                    sys_log(str(sys.exc_info()[1]), LOG_ERR)
                    continue
    elif os.path.isfile(path):
        try:
            rules.append(yara.compile(filepath = path))
        except:
            sys_log(str(sys.exc_info()[1]), LOG_ERR)

    return rules


def generate_hash(file):
    with open(file, 'rb') as f:
        filedata = f.read()
    try:
        sha256 = hashlib.sha256()
        sha256.update(filedata)
        return sha256.hexdigest()
    except:
        sys_log(str(sys.exc_info()[1]), LOG_ERR)
        return "Hash error"
    

def yr_file(file, rules):
    log = []
    description = "no description"

    for rule in rules:
        try:
            matches = rule.match(filepath = file)
            if matches:
                for match in matches:
                    if hasattr(match, 'meta'):
                        if 'description' in match.meta:
                            description = match.meta['description']
                    sha256 = generate_hash(file)
                    log.append({ "rulename" : str(match), "desc" : description, "filename" : file, "sha256" : sha256, "hostname" : platform.node()})
        except:
            sys_log(str(sys.exc_info()[1]), LOG_ERR)
            continue
    return log

    
def yr_dir(dir, rules, level):
    log = []
    description = "no description"

    # sorry for this..
    for root, dirs, filenames in os.walk(dir):
        if root[len(dir)+1:].count(os.sep) < level:
            for name in filenames:
                try:
                    file_path = os.path.join(root, name)
                    for rule in rules:
                        matches = rule.match(filepath = file_path)
                        if matches:
                            for match in matches:
                                if hasattr(match, 'meta'):
                                    if 'description' in match.meta:
                                        description = match.meta['description']
                                sha256 = generate_hash(file_path)
                                log.append({ "rulename" : str(match), "desc" : description, "filename" : file_path, "sha256" : sha256, "hostname" : platform.node()})
                except:
                    sys_log(str(sys.exc_info()[1]), LOG_ERR)
                    continue
    return log


def yr_proc(pid, rules):
    import psutil
    try:
        proc_name = psutil.Process(pid).name()
    except:
        sys_log(str(sys.exc_info()[1]), LOG_ERR)

    log = []
    description = "no description"

    for rule in rules:
        try:
            matches = rule.match(pid=pid)
            if matches:
                for match in matches:
                    if hasattr(match, 'meta'):
                        if 'description' in match.meta:
                            description = match.meta['description']
                    log.append({ "rulename" : str(match), "desc" : description, "proc" : proc_name, "pid" : pid, "hostname" : platform.node()})
        except:
            sys_log(str(sys.exc_info()[1]), LOG_ERR)
            continue
    return log



def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', action='store_true', default=False, dest='all_rules', help='Compile all rules.')
    parser.add_argument('-r', action='store', default=False, dest='rules', help='Compile single rule file or dir.')
    parser.add_argument('-t', action='store', default=False, dest='target', help='Run yara rule against target (pid/file/dir).', required=True)
    args = parser.parse_args()

    if(args.all_rules is False and args.rules is False):
        parser.print_help()
        sys.exit(0)
     
    parser = SafeConfigParser()
    parser.read(CONF_FILE)

    rpath = parser.get('main', 'rules_path') 
    repo_path = parser.get('git', 'repo_dir_path')
    repo_url = parser.get('git', 'repo_url')
    level = int(parser.get('main', 'scan_dir_level'))
    endpoint = parser.get('rest', 'endpoint')

    if(os.path.exists(repo_path)):
        update_rules(repo_url, repo_path)
    else:
        clone_rules(repo_url, repo_path)

    # run all rules
    if(args.all_rules):       
        rules = init_rules(rpath)
        if(os.path.exists(args.target)):
            if(os.path.isdir(args.target)):
                matches = yr_dir(args.target, rules, level)
            else:
                matches = yr_file(args.target, rules)
        else:
            matches = yr_proc(int(args.target), rules)
            
    
    if(args.rules):       
        rules = init_rules(args.rules)
        if(os.path.exists(args.target)):
            if(os.path.isdir(args.target)):
                matches = yr_dir(args.target, rules, level)
            else:
                matches = yr_file(args.target, rules)
        else:
            matches = yr_proc(int(args.target), rules)

    if(matches):
        sys_log(json.dumps((matches)), LOG_ALERT)
        rest_log(endpoint, matches)
    

if __name__ == '__main__':
    main()

