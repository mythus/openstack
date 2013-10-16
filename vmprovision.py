#!/usr/bin/env python

import paramiko,os,logging
import platform,socket,re
import subprocess as sub

logging.basicConfig(filename='/var/log/vmprovision.log', level=logging.DEBUG,
                        format='%(asctime)s %(message)s')

def getHostname():
	hostName = ''
	cmd = sub.Popen('/sbin/ifconfig',stdout=sub.PIPE,stderr=sub.PIPE)
	netInfo , error = cmd.communicate()
	ipAddr = re.search(r'addr:(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})', netInfo).group(1)
	try:
		hostName = socket.gethostbyaddr(ipAddr)[0]
	except Exception, e:
		logging.exception('Can not get hostname')
		exit(1)
	else:
		return hostName
def sftpKtab(rDir, rHost):

        sftpUser  = 'vmprov'
        sftpPass  = 'vmprov'
	filePath  = '/etc/krb5.keytab'
	rFile	  = rDir + getHostname() + '.'
	if os.path.isfile(filePath):
		exit(0)
        sftpTransport = paramiko.Transport((rHost, 22))
        try:
                sftpTransport.connect(hostkey=None, username=sftpUser, password=sftpPass)
                sftpConn = paramiko.SFTPClient.from_transport(sftpTransport)
  		sftpConn.get(rFile, filePath)

        except Exception, e:
                logging.exception('Error with ktab copy ')
		exit(1)
        else:
                logging.info('Ktab copied from: ' + rHost)
		os.chmod(filePath, 0600) 
        finally:
                sftpTransport.close()
def changeHostname():
	hostName = getHostname()
	if re.search(r'Red Hat', platform.linux_distribution()[0]):
		changeFile = ['/bin/sed', '-ie', '\'s/HOSTNAME=*/HOSTNAME=' + hostName + '/', '/etc/sysconfig/network']
		changeRun  = ['/bin/hostname', hostName ] 
		print changeFile,changeRun

		cmd = sub.Popen( changeRun, stdout=sub.PIPE,stderr=sub.PIPE)
		stdout, stderr = cmd.communicate()
		cmd = sub.Popen( changeFile, stdout=sub.PIPE,stderr=sub.PIPE)
		stdout, stderr = cmd.communicate()
	
if __name__ == "__main__":
	sftpServer = '10.32.29.101'
	sftpDir	   = '/ktabs/'
	#sftpKtab(sftpDir, sftpServer)
	changeHostname()
