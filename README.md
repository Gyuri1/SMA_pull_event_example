SMA Pull Events
====


This python example script pulls structured JSON-formatted events from Cisco Secure Malware Analytics
(formerly Threat Grid) and writes them to a log file.



# How to install:  

`pip install requests`  

 Download all of these files into local working directory!

 Please update the API_KEY, BASE_URL variables according to Your setup!
 
# How to use:  

 1. Use the default log path (`/var/log/Threatgrid.log`)  
  `python3 tg_pull_events.py`  

 2. Specify a custom log file with the short flag  
  `python3 tg_pull_events.py -l /tmp/my_threatgrid.log`

 3. Specify a custom log file with the long flag  
  `python3 tg_pull_events.py --logfile /home/user/logs/tg_events.log  

 4. View help  
  `python3 tg_pull_events.py --help`  
