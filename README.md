# palo-check-cert-expiry

## Check Palo Alto Certificate Expiry by API

Update the firewall endpoints with your production firewall IPs or hostnames within the prod dictionary and test firewalls in the test dictionary.

When testing you can easily switch between by changing the reference firewall endpoints.

The machine running the operation can either use a local postfix relay or send directly to another relay by modifying the 'smtp_server' variable.

The script will send an email if there are any certificates within a 30 day expiry period but this can be changed in the check_expiring_certs function to a time range of your choosing.

I've used this method to load env. variables: 
https://ip-life.net/loading-environment-variables-in-a-cron-job/

Utilises a bash helper script to start the python code.

A cron job should be defined to dictate how frequently the check runs:
20 6 * * 1-5 BASH_ENV=/path/to/.python_profile /path/to/scripts/palo-alto/check-certs.sh

Of course the firewalls need to allow API access to the user running the scripts and the machine IP to access the API.
