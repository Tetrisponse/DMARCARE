# DMARCE

The DMARCARE is the tool that cares about your DMARC!

DMARCARE is a python written tool that can extract the DMARC record from a specified domain 
and tell:

-it is possible to spoof the domain.

-what are the chances for attackers of success in spoofing the domain.

-what are the chances of monitoring any spoofing try.

-to which email address the aggregate/forensic/failure report is sent, and in what frequency.

-the reason for the failure report to be sent.

## Installation



```bash
git clone https://github.com/Tetrisponse/DMARCARE.git
cd DMARCARE
pip3 install -r requirements.txt
''''
'''bash
## Usage

python3 dmarcare.py -h 
[will show help message and exit.]

python3 dmarcare.py -d example.com 
[will extract and analyze the DMARC record of the specified domain.]

python3 dmarcare.py -f /path/to/domain_name_list.txt  
[will extract and analyze the DMARC record of any domain in the specified list.]

python3 dmarcare.py -f /path/to/domain_name_list.txt -o /path/to/output
[will extract and analyze the DMARC record of any domain in the specified list and saves the output.]
'''

```
## how DMARCARE works?
The DMARCARE works by getting the DMARC records with the "pydig" library. First, he validates the DMARC record. Then he analyzes the tag and responds accordingly. He knows how to extract domain names from URLs, so you won't have to worry about that ;-)



