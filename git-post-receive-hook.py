#!/usr/bin/env python
"""
This scirpt is pot-receive hook to allow applying changes per branch on the 
Puppt master servers via the r10k 
"""
import paramiko
import sys,logging

logging.basicConfig(filename='/var/log/gitr10khook.log', level=logging.DEBUG,format='%(asctime)s %(message)s')

def r10kExec(servers):
	"""
	Login to puppet master servers and excute r10k for every branch that was pushed.
	"""
	gitKey = '/home/git/.ssh/id_rsa'
	# Deploy wth modules 
	r10kCmd = 'r10k deploy environment -p'
	sshConn = paramiko.SSHClient()
	sshConn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	pKey  = paramiko.RSAKey.from_private_key_file(gitKey)
	pUser = 'puppetgit' 
	for puppetMaster in serverList:
		for line in sys.stdin:
			oldrev, newrev, ref = line.split() 
			branch = ref.split('/')[-1]
			try:
				sshConn.connect(puppetMaster, username=pUser, pkey=pKey)
				stdin, stdout, stderr = sshConn.exec_command(r10kCmd + ' ' + branch)
				sshConnErr = stderr.read()
				if sshConnErr:
					logging.error(sshConnErr)
					raise Exception('Error during deployment')
			except Exception, e:
				logging.exception('Error deploying environment ' + branch + 'for puppetMaster ' + puppetMaster )
			else:
				logging.info('Deployed environment ' + branch + ' for puppetMaster ' + puppetMaster)
	
if __name__ == '__main__':
	serverList = ['10.32.29.102']
	r10kExec(serverList)
