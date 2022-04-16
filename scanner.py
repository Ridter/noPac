#!/usr/bin/env python
#coding: utf-8
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from math import log

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials


import argparse
import logging
import sys
import string
from binascii import unhexlify
import ldapdomaindump
from utils.helper import *
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal

def banner():
    return """
███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                           
                                        
    """



def getTGT(username, options, kdc,requestPAC=True):
    userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if options.hashes is not None:
        __lmhash, __nthash = options.hashes.split(':')
    else:
        __lmhash = __nthash = ''
    aesKey = ''
    if options.aesKey is not None:
        aesKey = options.aesKey
    try:
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain,
                                                            unhexlify(__lmhash), unhexlify(__nthash), aesKey,
                                                            kdc,requestPAC=requestPAC)
        return tgt
    except Exception as e:
        logging.error(f"Error getting TGT, {e}")
        return None

def vulscan(username, password, domain, options):
    domain, username, password, lmhash, nthash = parse_identity(options)
    ldap_server, ldap_session = init_ldap_session(options, domain, username, password, lmhash, nthash)

    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
    MachineAccountQuota = 10
    for i in domain_dumper.getDomainPolicy():
        MachineAccountQuota = int(str(i['ms-DS-MachineAccountQuota']))

    logging.info(f'Current ms-DS-MachineAccountQuota = {MachineAccountQuota}')

    if options.all:
        dcinfo = get_dc_host(ldap_session, domain_dumper,options)
    else:
        dcinfo = {"dc": {"dNSHostName": options.dc_ip,"HostIP": options.dc_ip}}
        
    if len(dcinfo)== 0:
        logging.error("Cannot get domain info")
        exit()
    
    # Getting a ticket with PAC
    tgt = getTGT(username,options,options.dc_ip)
    if tgt:
        logging.info(f'Got TGT with PAC from {options.dc_ip}. Ticket size {len(tgt)}')
    else:
        logging.info(f'Get TGT wrong!')
        exit()
   
    for dc in dcinfo:
        if len(dcinfo[dc]['HostIP']) > 0:
            kdc = dcinfo[dc]['HostIP']
            tgt = getTGT(username,options,kdc, False)
            if tgt:
                logging.info(f"Got TGT from {dcinfo[dc]['dNSHostName']}. Ticket size {len(tgt)}")
        else:
            logging.error(f"Can't get DC ip from dns..")

if __name__ == '__main__':
    print(banner())

    parser = argparse.ArgumentParser(add_help = True, description = "SAM THE ADMIN CVE-2021-42278 + CVE-2021-42287 chain")

    parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on account parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-host', action='store',metavar = "hostname",  help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')
    group.add_argument('-dc-ip', action='store',metavar = "ip",  help='IP of the domain controller to use. '
                                                                      'Useful if you can\'t translate the FQDN.'
                                                                      'specified in the account parameter will be used')
    parser.add_argument('-use-ldap', action='store_true', help='Use LDAP instead of LDAPS')
    parser.add_argument('-all', action='store_true', help='Check all domain controllers')


    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.account)

    try:
        if domain is None or domain == '':
            logging.error('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        if options.no_pass:
            logging.info("Not supoort ccache")
            exit()

        vulscan(username, password, domain, options)
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error(f"Pls check your account. Error: {e}")
    except ldap3.core.exceptions.LDAPSocketOpenError as e:
         logging.error(f"If ssl error, add `-use-ldap` parameter to connect with ldap. Error: {e}")
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
