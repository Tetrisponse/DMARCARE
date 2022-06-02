import argparse
import re
from urllib.parse import urlparse
import pydig

#  saved variables and logo


logo = '''
   ______   _______  _______  _______  _______  _______  _______  _______ 
  (  __  \\ (       )(  ___  )(  ____ )(  ____ \\(  ___  )(  ____ )(  ____ \\
  | (  \\  )| () () || (   ) || (    )|| (    \\/| (   ) || (    )|| (    \\/
  | |   ) || || || || (___) || (____)|| |      | (___) || (____)|| (__    
  | |   | || |(_)| ||  ___  ||     __)| |      |  ___  ||     __)|  __)   
  | |   ) || |   | || (   ) || (\\ (   | |      | (   ) || (\\ (   | (      
  | (__/  )| )   ( || )   ( || ) \\ \\__| (____/\\| )   ( || ) \\ \\__| (____/\\
  (______/ |/     \\||/     \\||/   \\__/(_______/|/     \\||/   \\__/(_______/
                                                                  \u001b[34mBy Y4nush'''
line = '_________________________________________________________________________________________________' \
        '\n\n '

fo_to1 = ''
fo_to2 = ''
fo_to3 = ''
fo_policy = ''
fo_0 = "A DMARC failure report will be generated if the SPF and DKIM fails to produce an aligned “pass” result."
fo_1 = "A DMARC failure report will be generated if the SPF or DKIM fails to produce an aligned “pass” result."
fo_d = "A DKIM failure report will be generated if the DKIM authentication fails."
fo_s = "A SPF failure report will be generated if the SPF authentication fails."
domain = ''
rua_to = ''
ruf_to = ''
rua_mail = ''
ri = ' '
rua_addresses = ''
color = '32'
no_dmarc = u'''\u001b[31mNo DMARC records have been found! Please check that you wrote the domain in the 
correct syntax {example.com}.
Suppose you wrote the domain name correctly, and this message still pops. In that case, 
attackers can spoof the domain because he has no DMARC records or they were misconfigured.\n '''
no_pct_p_none = '\u001b[34;1m[+]\u001b[31;1mThe primary domain can be spoofed.\n'
no_pct_p_reject = '\u001b[34;1m[+]\u001b[32;1mIt is impossible to spoof the primary domain.\n'
no_pct_p_quarantine = "\u001b[34;1m[+]\u001b[32;1mIn case of spoofing the primary domain, the Email will go directly " \
                      "to the spam/junk folder.\n "
no_pct_sub_none = '\u001b[34;1m[+]\u001b[31;1mThe subdomain can be spoofed.\n'
no_pct_sub_reject = '\u001b[34;1m[+]\u001b[32;1mIt is impossible to spoof the subdomain.\n'
no_pct_sub_quarantine = "\u001b[34;1m[+]\u001b[32;1mIn case of spoofing the subdomain, the Email will go directly to" \
                        "the spam/junk folder.\n "
chance_for_alert_no_pct = "\u001b[" + color + "mChance to generate an alert that will be sent to the domain owner " \
                                              "while trying to spoof the domain or subdomain: "
no_dmarc_nc = '''No DMARC records have been found! Please check that you wrote the domain in the 
correct syntax {example.com}.
Suppose you wrote the domain name correctly, and this message still pops. In that case, 
attackers can spoof the domain because he has no DMARC records or they were misconfigured.\n'''
no_pct_p_none_nc = 'The primary domain can be spoofed.\n'
no_pct_p_reject_nc = 'It is impossible to spoof the primary domain.\n'
no_pct_p_quarantine_nc = "In case of spoofing the primary domain, the Email will go directly to the spam/junk " \
                         "folder.\n "
no_pct_sub_none_nc = 'The subdomain can be spoofed.\n'
no_pct_sub_reject_nc = 'It is impossible to spoof the subdomain.\n'
no_pct_sub_quarantine_nc = "In case of spoofing the subdomain, the Email will go directly to the spam/junk folder.\n "
no_pct_chance_for_alert = '''\u001b[32;1mChance to generate an alert that will be sent to the domain owner\nwhile trying to spoof the domain or subdomain:
[████████████████████████████████████████] 100/100%\n'''

# cli command interface
parser = argparse.ArgumentParser(description='Welcome to: DMARCARE the bot who cares about your DMARC records!')
parser.add_argument('-d', metavar='Domain', help='Specify a Domain [syntax: python3 dmarcare.py -d example.com]')
parser.add_argument("-f", metavar='File', help='Specify a list of domains(TXT file) [syntax: python3 dmarcare.py -f /path/to/list_of_domains].')
parser.add_argument("-o", metavar='Output', help='Specify path to output the results [syntax: python3 dmarcare.py -f /path/to/list_of_domains -o name_of_file ].')
args = parser.parse_args()

if args.d or args.f or args.h:
    print(logo)


# Function to create output file for the output


def output(text):
    if args.o:
        with open(args.o, "a", newline='') as o:
            o.write(text)


# function to extract and analyze any tag that is inside the DMARC record


def dmarc_check():
    global domain, rua_mail, ri, rua_to, ruf_to, no_pct_chance_for_alert, rua_addresses, \
        fo_to1, fo_policy, fo_to2, fo_to3, fo_0, line

    # extract the domain/subdomain from the input if it is an url
    try:

        if domain[:8] == "https://" or domain[:7] == "http://":
            domain = urlparse(domain).netloc
        else:
            pass
        if domain[:4] == "www.":
            domain = domain[4::]
        else:
            pass

        # the dig command from pydig module to get the DMARC record
        try:
            dmarc = (''.join(pydig.query('_dmarc.' + domain, 'TXT')))

            # extracts the rua/ruf mail addresses
            def mail_check(search, text):
                return re.search(r"\b{}\b".format(search), text, re.IGNORECASE) is not None

            # checks if there is a ruf address/es and extract.
            policy = "ruf=mailto"
            if mail_check(policy, dmarc):
                ruf_emails = dmarc[dmarc.index('ruf=mailto'):]
                ruf_addresses = re.findall(r"[a-z\d.\-+_]+@[a-z\d.\-+_]+\.[a-z]+", ruf_emails)
                ruf_index = dmarc.index('ruf=')
                rua_emails = dmarc[dmarc.index('rua=mailto'):int(ruf_index)]
                rua_addresses = re.findall(r"[a-z\d.\-+_]+@[a-z\d.\-+_]+\.[a-z]+", rua_emails)
                ruf_addresses = (" / ".join(ruf_addresses))
                rua_addresses = (" / ".join(rua_addresses))
                ruf_to = "The forensic and the failure report will be sent immediately to: " + ruf_addresses + \
                         "in case of a spoofing try that failed.\n"
                rua_to = "The aggregate report is sent to " + rua_addresses + " every 24 hours.\n"
            else:
                rua_to = ''
                ruf_to = ''

            # checks if there is a rua address/es and extract.
            policy = "rua=mailto"
            if mail_check(policy, dmarc):
                rua_emails = dmarc[dmarc.index('rua=mailto'):]
                emails = re.findall(r"[a-z\d.\-+_]+@[a-z\d.\-+_]+\.[a-z]+", rua_emails)
                rua_addresses = (" / ".join(emails))
                rua_to = "The aggregate report is sent to " + rua_addresses + " every 24 hours.\n"
            else:
                rua_to = ''

            # extracts the ri tag and convert the seconds to hour/s.
            policy = "ri="
            if mail_check(policy, dmarc):
                ri = re.findall(r'\d+', (dmarc[dmarc.index('ri=') + 3:]))[0]
                ri = int(int(ri) / 60 / 60)
                rua_to = "The aggregate report is sent to: " + rua_addresses + " every " + str(
                    ri) + " hour/s.\n"

            # extracts and analyze the first fo tag.
            def fo_check1(text1, index1, tag1, var1):
                global fo_policy, fo_0, fo_to1
                if text1[index1] == tag1:
                    fo_to1 = var1

            if "fo=" in dmarc:
                fo_policy = dmarc[dmarc.index("fo="):]

            try:
                fo_check1(fo_policy, 3, "0", fo_0)
                fo_check1(fo_policy, 3, "1", fo_1)
                fo_check1(fo_policy, 3, "d", fo_d)
                fo_check1(fo_policy, 3, "s", fo_s)
            except (Exception,):
                pass

            # extracts and analyze the second fo tag.
            def fo_check2(text2, index2, tag2, var2):
                global fo_policy, fo_to2
                if text2[index2] == tag2:
                    fo_to2 = var2

            try:
                if fo_policy[4] == ':':
                    pass
                fo_check2(fo_policy, 5, "0", fo_0)
                fo_check2(fo_policy, 5, "1", fo_1)
                fo_check2(fo_policy, 5, "d", fo_d)
                fo_check2(fo_policy, 5, "s", fo_s)
            except (Exception,):
                pass

            # extracts and analyze the third fo tag.
            def fo_check3(text3, index3, tag3, var3):
                global fo_policy, fo_to3
                if text3[index3] == tag3:
                    fo_to3 = var3

            try:
                if fo_policy[6] == ':':
                    pass
                fo_check3(fo_policy, 7, "0", fo_0)
                fo_check3(fo_policy, 7, "1", fo_1)
                fo_check3(fo_policy, 7, "d", fo_d)
                fo_check3(fo_policy, 7, "s", fo_s)
            except (Exception,):
                pass

            if "fo=" not in dmarc:
                fo_to1 = ''
                fo_to2 = ''
                fo_to3 = ''
            else:
                pass
            domain = domain + ":\n"

            # Validate if the DMARC record exists.
            if 'v=DMARC1' not in dmarc:
                no_dmarc1 = u'\u001b[31m' + domain + ": " + no_dmarc
                ri = ''
                rua_to = ''
                ruf_to = ''
                no_pct_chance_for_alert = ''
                fo_to1 = ''
                fo_to2 = ''
                fo_to3 = ''
                line = '\n_________________________________________________________________________________________________' \
                       '\n'
                output(line)
                output(domain)
                output(no_dmarc_nc)
                output('')
                print(no_dmarc1)
            else:
                pass

                dmarc_record = '\u001b[37;1m\n' + domain + dmarc + "\n"
                dmarc_record_output = dmarc + '\n'
                line = '\n_________________________________________________________________________________________________' \
                '\n'
                output(line)
                output(domain)
                output(dmarc_record_output)
                print(dmarc_record)

            # checks if the DMARC contains the pct tag and checks the p/sp tags policy.
            if "pct=" not in dmarc:
                def no_pct_policy_check(search, text):
                    return re.search(r"\b{}\b".format(search), text, re.IGNORECASE) is not None

                policy = "p=none"
                if not no_pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(no_pct_p_none_nc)
                    print(no_pct_p_none)

                policy = "sp=none"
                if not no_pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(no_pct_sub_none_nc)
                    print(no_pct_sub_none)

                policy = "p=reject"
                if not no_pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(no_pct_p_reject_nc)
                    print(no_pct_p_reject)

                policy = "sp=reject"
                if not no_pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(no_pct_sub_reject_nc)
                    print(no_pct_sub_reject)

                policy = "p=quarantine"
                if not no_pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(no_pct_p_quarantine_nc)
                    print(no_pct_p_quarantine)
                policy = "sp=quarantine"
                if not no_pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(no_pct_sub_quarantine_nc)
                    print(no_pct_sub_quarantine)
                # outputs the chance for alert.
                output_alert_chance = "There is a 100% chance that an alert will be generated in case of spoofing.\n"
                output(output_alert_chance)

                # prints/outputs the ruf/rua addresses
                print(no_pct_chance_for_alert)
                print("\u001b[37;1m" + ruf_to)
                print("\u001b[37;1m" + rua_to)
                output(rua_to)
                output(ruf_to)

                # prints/output the fo tag policy
                print("\u001b[34m" + fo_to1)
                output(fo_to1)
                print("\u001b[34m" + fo_to2)
                output(fo_to2)
                print("\u001b[34m" + fo_to3)
                output(fo_to3)
            else:
                pass

            # checks if the DMARC contains the pct tag and checks the p/sp tags policy.
            if "pct=" in dmarc:
                color_pct = '32'

                # Extracts the pct tag and calculates the chance for spoofing
                pct = re.findall(r'\d+', (dmarc[dmarc.index('pct') + 4:]))[0]
                chance = 100 - int(pct)

                # Change the color depends on the chance to spoof
                if chance > 50:
                    color_pct = color_pct.replace('32', '31')

                # Creates progress toolbar
                calc = ((int(pct) / 5) * 2)
                piss = u"\u001b[" + color_pct + ";1m[" + ("█" * int(calc) + "]")

                # variables
                p_none_nc = "The primary domain can be spoofed.\n"
                p_reject_nc = "There is a " + str(chance) + "% chance of spoofing the primary domain.\n"
                p_quarantine_nc = "There is a " + str(
                    pct) + "% chance that in the case of spoofing the primary domain, the Email will go directly to " \
                           "the spam/junk folder of the receiver.\n"
                sub_none_nc = "The subdomain can be spoofed.\n"
                sub_reject_nc = "There is a " + str(chance) + "% chance of spoofing the subdomain.\n"
                sub_quarantine_nc = "There is a " + str(
                    pct) + "% chance that in the case of spoofing the subdomain, the Email will go directly to " \
                           "the spam/junk folder of the receiver.\n"
                p_none = "\u001b[34;1m[+]\u001b[31;1mThe primary domain can be spoofed.\n"
                p_reject = "\u001b[34;1m[+]\u001b[" + color_pct + "mThere is a " + str(
                    chance) + "% chance of spoofing the primary domain.\n"
                p_quarantine = "\u001b[34;1m[+]\u001b[" + color_pct + "mThere is a " + str(
                    pct) + "% chance that in the case of spoofing the primary domain, the Email will go directly to " \
                           "the spam/junk " \
                           "folder of the receiver.\n"
                sub_none = "\u001b[34;1m[+]\u001b[31;1mThe subdomain can be spoofed.\n"
                sub_reject = "\u001b[34;1m[+]\u001b[" + color_pct + "mThere is a " + str(
                    chance) + "% chance of spoofing the subdomain.\n"
                sub_quarantine = "\u001b[34;1m[+]\u001b[" + color_pct + "mThere is a " + str(
                    pct) + "% chance that in the case of spoofing the subdomain, the Email will go directly to the " \
                           "spam/junk " \
                           "folder of the receiver.\n "

                def pct_policy_check(search, text):
                    return re.search(r"\b{}\b".format(search), text, re.IGNORECASE) is not None

                policy = "p=none"
                if not pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(p_none_nc)
                    print(p_none)

                policy = "sp=none"
                if not pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(sub_none_nc)
                    print(sub_none)

                policy = "p=reject"
                if not pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(p_reject_nc)
                    print(p_reject)

                policy = "sp=reject"
                if not pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(sub_reject_nc)
                    print(sub_reject)

                policy = "p=quarantine"
                if not pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(p_quarantine_nc)
                    print(p_quarantine)

                policy = "sp=quarantine"
                if not pct_policy_check(policy, dmarc):
                    pass
                else:
                    output(sub_quarantine_nc)
                    print(sub_quarantine)

                print(
                    "\u001b[" + color_pct + "mChance to generate an alert that will be sent to the domain "
                                            "owner\nwhile trying to spoof the domain or subdomain:")

                # Prints/outputs the chance for spoofing/monitoring
                print(piss, str(pct) + "/100%\n\n")
                output_alert_chance = "There is a " + pct + "% chance that an alert will be generated in case of spoofing.\n"
                output(output_alert_chance)

                # Prints/outputs the fo tags policy
                print("\u001b[34m" + fo_to1)
                fo_to1_output = fo_to1 + "\n"
                output(fo_to1_output)
                print("\u001b[34m" + fo_to2)
                fo_to2_output = fo_to2 + "\n"
                output(fo_to2_output)
                print("\u001b[34m" + fo_to3)
                fo_to3_output = fo_to3 + "\n"
                output(fo_to3_output)

                # prints/outputs the rua/ruf addresses.
                print("\u001b[37;1m" + ruf_to)
                print("\u001b[37;1m" + rua_to)
                output(rua_to)
                output(ruf_to)
        except (Exception,):
            pass

    except (Exception,):
        pass


if args.d:
    domain = args.d
    dmarc_check()

if args.f:
    with open(args.f) as f:
        for line in f:
            domain = line.strip()
            dmarc_check()
