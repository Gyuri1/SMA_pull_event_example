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


# Important Notes

** Pagination ** — The limit parameter is set to 500. If your organisation has more submissions in the time window, you will need to paginate by incrementing offset. The response includes current_item_count to help determine if more pages exist.

** Time window ** — Adjust the after and before parameters in the params dict to match your desired query range.

** Permissions ** — The user running the script must have write access to the target log file path.

** Config security ** — Protect tg_config.py with chmod 600 tg_config.py.

** API key in URL ** — The v2 endpoint passes the API key as a query parameter. 
Ensure you use HTTPS (which the default base URL does) so the key is encrypted in transit.


# More info:  

https://developer.cisco.com/threat-grid/  

https://ciscosecurity-tg-00-integration-workflows.readthedocs-hosted.com/en/latest/tg/query.html#entity-searches  

