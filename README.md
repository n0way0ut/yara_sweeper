# Yara Sweeper

In a live Incident Response situation yara is useful for deploying across an enterprise environment, scanning processes running 
in memory or files residing on disk. 
The aim of this tool is to run yara rules in a large scale environment. 
It works on Linux, Windows and OSX.


# Use cases

 - On demand sweep.  During Incident Response, quickly create your yara rules and push on rules git repository, 
invoke the agent to perform the scan on files, directory or running process. 
 - Continuous IOC monitoring.   Collect a library of yara rules based on IOCs collected over time, and create 
scheduled tasks to run regularly sweeping the endpoint for specified yara rules. Forward the syslog events to SIEM.


# How it works

 - Invoke agent on-demand with salt/puppet/ansible on linux, wmi/psexec on windows or jamf on OSX, or create a scheduled task. 
 - Agent clones the yara git repository if it is the first run or just pulls new rules. 
 - Agent runs against file, directory or process id. If there are matches all details are sent to local syslog and to remote REST server.

 - REST server has a web dashboard to monitor and filter the matched results from all endpoints.

    ```
    $ ./yara_sweeper.py -h
    usage: yara_sweeper.py [-h] [-a] [-r RULES] -t TARGET
    
    optional arguments:
    -h, --help  show this help message and exit
    -a          Compile all rules.
    -r RULES    Compile single rule file or dir.
    -t TARGET   Run yara rule against target (pid/file/dir).

    $ ./yara_sweeper.py -r rules/malware/MALW_LinuxBew.yar -t /tmp/linuxbrew.exe
    $ ./yara_sweeper.py -r rules/malware/ -t /tmp/linuxbrew.exe
    $ ./yara_sweeper.py -r rules/malware/MALW_LinuxBew.yar -t 1234
    The first parameter is a path that needs to be on target hosts (see config.ini file).

    syslog log sample
    Dec 10 22:44:55 xps /yara_sweeper.py[24767]: [{"rulename": "LinuxBew", "desc": "Linux.Bew Backdoor", "filename": "linuxbrew.exe", "sha256": "80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06", "hostname": "xps"}]
    Dec 10 22:45:40 xps /yara_sweeper.py[24800]: [{"rulename": "LinuxBew", "desc": "Linux.Bew Backdoor", "proc": "vim", "pid": 24460, "hostname": "xps"}]
    ```



![Yara Sweeper Dashboard](https://i.imgur.com/uiu8qjw.png)

# Configuration

    [main]
    rules_path = rules
    scan_dir_level = 1
    
    [git]
    repo_url = https://github.com/Yara-Rules/rules 
    repo_dir_path = rules
    #user = <username>
    #pwd = <password>
    
    [rest]
    endpoint = http://127.0.0.1:8080/post_match 
    #user = <username>
    #pwd = <password>


# Notes

The initial idea comes from https://www.sans.org/reading-room/whitepapers/forensics/intelligence-driven-incident-response-yara-35542

# TODO

Git and REST server authentication
Reuse cached compiled rules
Upload matched files automatically on REST server
