#!/usr/bin/env python3

"""
## DNS SCRAPER  ####
 Requirement: Access to a security audit role with read access to the
 route53, ec2 elastics IPs, and so on.
 Setup local environment with aws-vault.
 To run for all accounts: aws-vault exec dgs_iam -- pipenv run ./dns-scraper.py all
"""

import argparse
import socket
import json
import boto3

def loadconfig(configlocation='teams.config'):
    """ Import config from json file at (default) 'teams.config' """
    conf = {}
    with open(configlocation, 'r') as conffile:
        conf = json.load(conffile)
    return conf

class AccountScraper(object):
    """ An accountscraper object has the credentials to an assumed account
    in order to be able to scrape the route53 contents thereof """
    def __init__(self, sts_client, account, arn):
        # Call the assume_role method of the STSConnection object and pass the
        # role ARN and a role session name.

        assumed_role_object = sts_client.assume_role(
            RoleArn=arn,
            RoleSessionName=account
        )

        credentials = assumed_role_object['Credentials']
        self.credentials = credentials

        # Use the temporary credentials that AssumeRole returns to make a
        # connection to Amazon route53
        r53client = boto3.client(
            'route53',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )
        self.r53client = r53client


    def scrape_account(self):
        """ scrapes route53 records listed in the account """
        hosted_zone = self.r53client.list_hosted_zones()
        hosted_zone_list = [i['Id'].split('/')[2] for i in hosted_zone['HostedZones']]
        tld_list = [i['Name'] for i in hosted_zone['HostedZones']]
        eip_list = self.get_eip()
        dns_list = self.get_dns(hosted_zone_list)
        return dns_list, tld_list, eip_list

    def get_dns(self, hosted_zone_list):
        """ Iterates through hosted zones and returns a
        dictionary of domains and record types
        Only filtering based off A and CNAME """
        dns_list = []
        for hz_id in hosted_zone_list:
            record = self.r53client.list_resource_record_sets(HostedZoneId=hz_id)
            for i in record['ResourceRecordSets']:
                dns_list.append(Dns(i['Name'][:-1], i['Type']))  # removes period from name
        return dns_list

    def get_eip(self):
        """ scrapes list of elastic IPs in account """

        filters = [
            {'Name': 'domain', 'Values': ['vpc']}
        ]
        eip_list = []
        regions = (boto3.session.Session()).get_available_regions('ec2') # get all regions
        for region_name in regions:
            # Connect to ec2
            ec2client = boto3.client(
                'ec2',
                aws_access_key_id=self.credentials['AccessKeyId'],
                aws_secret_access_key=self.credentials['SecretAccessKey'],
                aws_session_token=self.credentials['SessionToken'],
                region_name=region_name
            )
            response = ec2client.describe_addresses(Filters=filters)
            eip_list += [EIP(i, region_name) for i in response['Addresses']]
        return eip_list


class EIP(object):
    """ A Elastic IP object- stores and displays records for EIP objects """
    def __init__(self, eip, region):
        """ constructor for an elastic IP (EIP) record object """
        self.region = region
        # self.allocation_id = eip.get('AllocationId')
        # self.association_id = eip.get('AssociationId')
        self.domain = eip.get('Domain')
        # self.network_interface_id = eip.get('NetworkInterfaceId')
        # self.network_interface_owner_id = eip.get('NetworkInterfaceOwnerId')
        # self.tags = eip.get('Tags')
        self.private_ip = eip.get('PrivateIpAddress')
        self.public_ip = eip.get('PublicIp')
        self.instance_id = eip.get('InstanceId')

    def is_attached(self):
        """ is the elastic ip attached to an instance """
        return self.instance_id is None

    def get_dict(self):
        """ return the object and relevant values as a dict """
        return {"Region": self.region,
                "PublicIp": self.public_ip,
                "PrivateIp": self.private_ip,
                "InstanceId": self.instance_id}


class Dns(object):
    """ A DNS object- has functionality around resolving/testing DNS records."""
    def __init__(self, dns, recordtype):
        """ constructor for a DNS record object """
        self.dns = dns
        self.recordtype = recordtype
        self.ip = None
        self.public = None
        self.resolved = None

    def is_public(self):
        """ returns true if the DNS record is resolvable and public """
        return bool(self.resolved) and bool(self.public)

    def is_private(self):
        """" returns true if the DNS records is resolvable and not public """
        return bool(self.resolved) and not bool(self.public)

    def is_unresolveable(self):
        """ returns true if the DNS records can't be resolved """
        return not bool(self.resolved)

    def resolve(self):
        """ Attempts to resolve the DNS, and updates internal values based
        on how the DNS resolves- is it public/private/unresolveable? """
        private_ips = ('10.', '172.16.', '172.31.', '192.168')
        if(self.recordtype not in ['A', 'CNAME']):
            self.resolved = False
        else:
            self.resolved = True
            try:
                hsn = socket.gethostbyname(self.dns)
                self.ip = hsn
                self.public = not hsn.startswith(private_ips)
            except (socket.error, socket.herror, socket.gaierror, socket.timeout) as _:
                self.resolved = False

    def get_dict(self):
        """ return the object and values as a dict """
        return {"Name": self.dns,
                "Type": self.recordtype,
                "IP": self.ip,
                "Public": self.is_public(),
                "Private": self.is_private(),
                "Unresolved": self.is_unresolveable()}

def processresults(account, dns_list, tld_list, eip_list, options):
    """ helper function that formats/prints results of scraping.
    default is printing to terminal """
    if options is None:
        filterfunc = lambda d: d.is_public()
        printterminal(account, dns_list, tld_list, eip_list, filterfunc)
    else:
        (options["function"])(account, dns_list, tld_list, eip_list, options["filterfunc"])

def printterminal(account, dns_list, tld_list, eip_list, filterfunc):
    """ prints results to standard out """
    print()
    print(account)
    print("DNS".ljust(70), "IP")
    filtered_dns_list = filter(filterfunc, dns_list)

    for i in filtered_dns_list: #filter(lambda d: d.is_public(), dns_list):
        print(i.dns.ljust(70), i.ip)

    # print([json.dumps(i.get_dict()) for i in dns_list])
    # print(json.dumps(tld_list))

    print("TLDs")
    for tld in tld_list:
        print(tld)

    print("EIPs")
    for eip in eip_list:
        print(eip.public_ip
              + "\t" + eip.private_ip
              + "\t" + str(eip.instance_id).ljust(20)
              + "\t\t" + eip.region)

class AWSAuthenticationError(Exception):
    """ wrapper for aws authentication errors to add some more information """
    def __init__(self, account, arn):
        self.message = "Error authenticating to AWS"
        self.account = account
        self.arn = arn
        super().__init__(self.message)
    def __str__(self):
        return self.message +" account:`"+self.account+"` arn:`"+self.arn+"`"

def scrape_aws(conf, servicename, printoptions):
    """ scrapes the route53 records and elastic ips associated with the named account """
    sts_client = boto3.client('sts')
    accountdict = conf[servicename]
    for account, arn in accountdict:
        try:
            accountscraper = AccountScraper(sts_client, account, arn)
            dns_list, tld_list, eip_list = accountscraper.scrape_account()

            for dns in dns_list:
                dns.resolve()

            processresults(account, dns_list, tld_list, eip_list, printoptions)
        except sts_client.exceptions.ClientError as excp:
            raise AWSAuthenticationError(account, arn) from excp


if __name__ == "__main__":

    loadconfig()
    PARSER = argparse.ArgumentParser()
    PARSER.add_argument("servicename")
    ARGS = PARSER.parse_args()

    SERVICENAME = ARGS.servicename
    AWSCONF = loadconfig()
    if SERVICENAME == "all":
    # TODO option for argparse for none = all
    # TODO option to print only ips or only dns
    # TODO option to export json
        for k in AWSCONF:
            scrape_aws(AWSCONF, k, None)
    else:
        scrape_aws(AWSCONF, SERVICENAME, None)
