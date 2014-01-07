#!/usr/bin/env python

"""
Accept action , ip address and common name of the openvpn client connecting and 
generate rule accoring to yaml file with ip addresses that client may access.
Everything except those ip addresses if blocked for the client.
"""
import sys, yaml, subprocess, logging

logging.basicConfig(filename='/var/log/openvpn_firewall.log', level=logging.DEBUG,
                        format='%(asctime)s %(message)s')

def firewallRules( action, cName, ipAddr, virtualMachine=[] ):
	
	iptables='/sbin/iptables'
	opts={
		'addDelRuleFlag'	: '',
		'addDelChainFlag'	: '',
		'iptables'		: '/sbin/iptables',
		'chain'			: cName,
		'vmAddrs'		: ','.join(virtualMachine),
		'clientAddr'		: ipAddr
	}
        if action == 'add':
                opts['addDelRuleFlag'] = '-A'
                opts['addDelChainFlag']= '-N'
        elif action == 'delete':
                opts['addDelRuleFlag'] = '-D'
                opts['addDelChainFlag']= '-X'
        else:
                logging.error('No action specified - add or remove rules?')
                sys.exit(1)

	cmdAddChain 	= '{iptables} {addDelChainFlag} {chain}'.format(**opts)
	cmdChain1 	= '{iptables} {addDelRuleFlag} FORWARD -i tun0 -s {clientAddr}  -j {chain}'.format(**opts)
	cmdChain2 	= '{iptables} {addDelRuleFlag} FORWARD -o tun0 -d {clientAddr}  -j {chain}'.format(**opts)
	cmdRuleEnd 	= '{iptables} {addDelRuleFlag} {chain} -j REJECT --reject-with icmp-admin-prohibited'.format(**opts)
	cmdRule1 	= '{iptables} {addDelRuleFlag} {chain} -s {vmAddrs} -j ACCEPT'.format(**opts)
	cmdRule2	= '{iptables} {addDelRuleFlag} {chain} -d {vmAddrs} -j ACCEPT'.format(**opts)
	actionArray 	= [cmdAddChain,cmdChain1,cmdChain2,cmdRule1,cmdRule2,cmdRuleEnd]
	if action == 'delete':
		actionArray.reverse()

	for cmdIp in actionArray :
		print cmdIp
		try:
			iptablesProc = subprocess.Popen(cmdIp,
       	                                         shell 	= True,
       	                                         stderr = subprocess.PIPE,
       	                                         stdout = subprocess.PIPE)
			iptablesStdout , iptablesStderr = iptablesProc.communicate()
		except Exception as detail:
			logging.exception('Exception while executing iptables command for client: ' +  cName)
			sys.exit(1)

		if iptablesStderr:
			logging.error('Error while executing iptables command for client: ' + cName + '\n' + iptablesStderr)
#			sys.exit(1)


if __name__ == '__main__':
	clientsAclFilePath='/root/clients.yaml'
	logging.info('Adding rules for client: '  sys.argv[1:4])
	action,ipAddr,cName = sys.argv[1:4]
	try:        
		with open(clientsAclFilePath,'r') as cAcl:
               	 	allClientsAcl = yaml.load(cAcl)
	except Exception as detail:
		logging.exception('Failed to extract yaml from file: ' +  clientsAclFilePath )
		sys.exit(1)
	if cName not in allClientsAcl:
		logging.error('Common name of the user not specified in the yaml file: ' + clientsAclFilePath)
		sys.exit(1)
	firewallRules(action,cName,ipAddr,allClientsAcl[cName])

