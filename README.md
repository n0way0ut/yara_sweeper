# Yara Sweeper

The aim of this tool is to run yara rules in a large scale environment.
Yara sweeper is useful to be used, in a live Incident Response situation, to scan processes running in memory 
or files residing on disk. 

It works on Linux, Windows and OSX.


## Use cases

 - **On demand sweep**.  During Incident Response, invoke the agent to perform the scan on files, directory 
 or running process with a quickly created yara rule pushed on git repository.  
 - **Continuous IOCs monitoring**.   Collect a library of yara rules based on IOCs built over time, and create 
scheduled tasks to run regularly sweeping on the endpoint for specified yara rules; the syslog events generated are sent 
to SIEM.


## How it works

 >- Agent: yara_sweeper.py
 >- Agent config: config.ini
 >- REST server: rest.py
 
 
 1. Agent is invoked via a scheduled task or on-demand with linux salt/puppet/ansible, windows wmi/psexec or OSX salt/jamf.
 2. Agent checks if the yara repository dir exists then pulls new rules, if any, or clones the whole yara git repo.
 3. Agent runs against files, directory or process id. If there is any match it sends all details to local syslog 
 and to remote REST server.

 - REST server has a web dashboard to monitor and filter the matched rules from all endpoints. All data are stored on a sqlite DB.

    ```
    $ ./yara_sweeper.py -h
    usage: yara_sweeper.py [-h] [-a] [-r RULES] -t TARGET
    
    optional arguments:
    -h, --help  show this help message and exit
    -a          Compile all rules.
    -r RULES    Compile single rule file or dir.
    -t TARGET   Run yara rule against target (pid/file/dir).

    The first parameter (-r) is rules path (dir or single file) and it is located on endpoint host. (see config.ini file for all rules).
    $ ./yara_sweeper.py -r rules/malware/MALW_LinuxBew.yar -t /tmp/linuxbrew.exe
    $ ./yara_sweeper.py -r rules/malware/ -t /tmp/linuxbrew.exe
    $ ./yara_sweeper.py -r rules/malware/MALW_LinuxBew.yar -t 24460

    syslog logs sample
    Dec 10 22:44:55 xps /yara_sweeper.py[24767]: [{"rulename": "LinuxBew", "desc": "Linux.Bew Backdoor", "filename": "linuxbrew.exe", "sha256": "80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06", "hostname": "xps"}]
    Dec 10 22:45:40 xps /yara_sweeper.py[24800]: [{"rulename": "LinuxBew", "desc": "Linux.Bew Backdoor", "proc": "vim", "pid": 24460, "hostname": "xps"}]
    ```

----------

![Yara Sweeper Dashboard](https://i.imgur.com/uiu8qjw.png)

## Configuration

    [main]
    rules_path = rules   # dir path of stored rules on endpoint.
    scan_dir_level = 1   # scan dept level directory (/a/b/c/d if it is 2 the scan stops to /a/b/ dir)
    
    [git]
    repo_url = https://github.com/Yara-Rules/rules    # yara rule repository 
    repo_dir_path = rules                             # dir path for yara rule repo 
    #user = <username>
    #pwd = <password>
    
    [rest]
    endpoint = http://127.0.0.1:8080/post_match       # rest server endpoint
    #user = <username>
    #pwd = <password>


## Notes

The initial idea comes from https://www.sans.org/reading-room/whitepapers/forensics/intelligence-driven-incident-response-yara-35542

## TODO

Git and REST server authentication

Reuse cached compiled rules

Upload matched files automatically on REST server

