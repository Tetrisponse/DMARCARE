# DMARCE

The DMARCARE is the tool that cares about your DMARC!

DMARCARE is a python written tool that can extract the DMARC record from a specified domain 
and tell:

-if it is possible to spoof the domain.

-what are the chances for attackers to succeed in spoofing the domain or the subdomain.

-what are the chances of monitoring any spoofing try.

-to which email address the aggregate/forensic/failure report is sent, and in what frequency.

-the reason for the failure report to be sent.

## How does DMARCARE work?
The DMARCARE works by getting the DMARC records with the "pydig" library.

At first, he validates the DMARC. After the DMARC was found and validated. He analyzes the tag and responds accordingly.

He also knows how to extract domain names from URLs, so you won't have to worry about that ;-)
## Supported Operating Systems:
* Debian Linux OS
* The tool Was tested on Ubuntu 20.04\Kali Linux 2022.1
## Supported Python versions:
* Python 3.5v or higher.

## Installation



```bash
git clone https://github.com/Tetrisponse/DMARCARE.git
cd DMARCARE
pip3 install -r requirements.txt
```
## Usage
```bash
python3 dmarcare.py -h 
[will show help message and exit.]

python3 dmarcare.py -d example.com 
[will extract and analyze the DMARC record of the specified domain.]

python3 dmarcare.py -f /path/to/domain_name_list.txt  
[will extract and analyze the DMARC record of any domain in the specified list.]

python3 dmarcare.py -f /path/to/domain_name_list.txt -o /path/to/output
[will extract and analyze the DMARC record of any domain in the specified list and saves the output.]

```
## License
[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)
