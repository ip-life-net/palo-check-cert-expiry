#!/usr/bin/env python3

# Check Certs on Palo Alto Firewalls and if nearing expiry date send an alert

from datetime import datetime
from panos.firewall import Firewall
import paloalto
import smtplib

# Firewall hosts
firewall_endpoints = {
    'prod': [
        'prod.firewall.1',
        'prod.firewall.2',
        'prod.firewall.3',
        'prod.firewall.4',
        'prod.firewall.5'
        ],
    'test': [
        'test.firewall.1'
        ]
    }
firewall_hosts = firewall_endpoints['prod']  # Select firewall endpoints

# List containers
db_name = []
db_exp_date = []

# Counter
counter = 0

# Fetch todays date
today = datetime.now()

# Send mail using local postfix
port = 25
smtp_server = "localhost"
sender_email = "Python@somedomain.com"
receiver_email = "some.recipient@somedomain.com"
message = """\
From: {sender}
Subject: Palo Alto Certificate Warning
Date: {date}
To: {recipient}

There are {count} certificates nearing expiry!
Please check all production Palo Alto firewalls
for certificates nearing expiration.
Palo Alto Primary Firewalls:
{firewall}

Certs nearing expiry:
{certs}

This message has been sent from Python."""


# Create datetime object from string
def get_datetime_object(dt_string):
    """
    Return datetime object from string

    """
    dt_object = datetime.strptime(dt_string, '%b %d %H:%M:%S %Y %Z')
    return dt_object


def check_expiring_certs(indict):
    """
    Check if certs on the firewall are nearing expiry within 30 days

    """
    global counter
    cert_names = []
    for k, v in indict.items():
        diff = get_datetime_object(k[k.find("(")+1:k.find(")")]) - today
        if diff.days <= 30:  # Expiry within days (30 standard)
            counter = counter + 1
            cert_names.append(v)
    return cert_names


for i in firewall_hosts:
    while True:
        try:
            fw = Firewall(i, api_key=paloalto.return_token())
            raw_data = fw.op('show sslmgr-store config-certificate-info')
            data = raw_data.find('.//result')
            cert_list = data.text.splitlines()
            break
        except Exception as e:
            print(i, e)

# Create Cert lists
for cert in cert_list:
    if 'db-exp-date' in cert:
        db_exp_date.append(cert.strip())
    elif 'db-name' in cert:
        db_name.append(cert.strip())

# Create Cert Dictionary
cert_dict = dict(zip(db_exp_date, db_name))

# Run function
expiring_cert_list = check_expiring_certs(cert_dict)

# Transform to set
expiring_cert_set = set(expiring_cert_list)

# Send an email if expiry is nearing 30 days
if counter >= 1:
    print('There are {0} certificates nearing expiry!'.format(counter))
    try:
        server = smtplib.SMTP(smtp_server, port)
        server.ehlo()  # Can be omitted
        server.sendmail(
            sender_email,
            receiver_email,
            message.format(
                sender=sender_email,
                date=today,
                recipient=receiver_email,
                count=counter,
                firewall='\n'.join(firewall_hosts),
                certs='\n'.join(expiring_cert_set)
                )
            )
    except Exception as e:
        # Print any error messages to stdout
        print(e)
    finally:
        server.quit()
