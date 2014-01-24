#!/usr/bin/env python
"""
This scirpt is web pot-receive hook to allow applying changes per branch on the
Puppt master servers via the r10k.
"""
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import paramiko
import logging
import sys
import json


logging.basicConfig(filename='/var/log/gitr10kwebhook.log', level=logging.DEBUG,format='%(asctime)s %(message)s')

def r10kExec(servers,gitKey,pUser,branch):
        """
        Login to puppet master servers and excute r10k for every branch that was pushed.
        """
        # Deploy wth modules
        r10kCmd = 'r10k deploy environment -p'
        sshConn = paramiko.SSHClient()
        sshConn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pKey = paramiko.RSAKey.from_private_key_file(gitKey)
	try:
		if int(branch['after']) == 0:
			delBranch = True
	except ValueError:
		delBranch = False
        for puppetMaster in serverList:
                branch = branch['ref'].split('/')[-1]
                try:
                        sshConn.connect(puppetMaster, username=pUser, pkey=pKey)
                        stdin, stdout, stderr = sshConn.exec_command(r10kCmd + ' ' + branch)
                        sshConnErr = stderr.read()
			if delBranch:
				logging.info('Deleteing environment: ' + branch)
				continue
                        if sshConnErr:
				raise Exception('ErrorDeploy' + sshConnErr)
                except Exception, e:
                        logging.exception('Error deploying environment ' + branch + ' for puppetMaster ' + puppetMaster )
                else:
                        logging.info('Deployed environment ' + branch + ' for puppetMaster ' + puppetMaster)
        

class PostHandler(BaseHTTPRequestHandler):
	def do_POST(self):
		cont_len = int(self.headers.getheader('content-length'))
		post_body = self.rfile.read(cont_len)
		self.send_response(200, 'OK')
		self.end_headers()
		logging.info('POST BODY' + post_body)
		branch = json.loads(post_body)
		r10kExec(serverList,gitKey,pUser,branch)

if __name__ == '__main__':
	serverList = ['172.31.200.32']
	gitKey = '/home/git/.ssh/id_rsa'
	pUser  = 'puppetgit'
	ipAddr,port = sys.argv[1:3]
	httpServer = HTTPServer((ipAddr,int(port)), PostHandler)
	try:
		httpServer.serve_forever()
	except Exception as e:
		logging.exception('Web server had an error' + e )	
