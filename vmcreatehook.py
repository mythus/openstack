#!/usr/bin/env python

from kombu import Connection, Exchange, Queue
import paramiko,os,logging,re
import dns.tsigkeyring
import dns.update
import dns.query
import dns.resolver

logging.basicConfig(filename='/var/log/vmprovision.log', level=logging.DEBUG,
			format='%(asctime)s %(message)s')

def genHostname(ipAddr):
	"""
	Make uniq hostname from ip address
        """
	domain = '.osdev.skrill.net.'
	if ipAddr:
		return 'vm-' + '-'.join(ipAddr.split('.')) + domain
	else:
		return ''

def ktabUpdate (hostName, action='create'):
	"""
	Ssh to KDC and execute remote scripts which use kadmin to
	create and export the host principle.
	"""
	if not hostName:
		logging.error('Hostname not specified, exiting this iteration' )
		return 1
	kdc     = 'kdc1.moneybookers.net'
	kUser   = 'vmprov'
	kKey    = '/root/.ssh/id_rsa'
	kCreate = 'sudo /root/bin/create-host-principal.sh'
	kExport = 'sudo /root/bin/export-host-principal-vmprov.sh'
	rKeytab	= '/home/vmprov/ktabs/'
	lKeytab = '/home/vmprov/ktabs/'
	sshConn = paramiko.SSHClient()
	sshConn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	pKey  = paramiko.RSAKey.from_private_key_file(kKey)
	if action == 'create':
		try:
			sshConn.connect(kdc, username=kUser, pkey=pKey)
			stdin, stdout, stderr = sshConn.exec_command(kCreate + ' ' + hostName)
			sshConnErr = stderr.read()
			if sshConnErr:
				if re.search('Principal or policy already exists' , sshConnErr):
					logging.info('Host ' + hostName + ' already exists')
				else:
					raise Exception('Unknown error during keytab creation')
			stdin, stdout, stderr = sshConn.exec_command(kExport + ' ' + hostName)
			sshConnErr = stderr.read()
			if sshConnErr:
				raise Exception('Unknown error during keytab export')
		except Exception, e:
			logging.exception('Error with generating keytab for ' + hostName )
		else:
			logging.info('Keytab exported for ' + hostName)
		finally:
			sshConn.close()

		scpTransport = paramiko.Transport((kdc, 22))
		rFile = rKeytab + hostName
		lFile = lKeytab + hostName
		try:
			scpTransport.connect(hostkey=None, username=kUser, pkey=pKey)
			scpConn = paramiko.SFTPClient.from_transport(scpTransport)
			scpConn.get(rFile, lFile)
	
		except Exception, e:
			logging.exception('Error with ssh copy from kdc for file: ' + hostName)
		else:
			logging.info( 'Keytab file copied from kdc for host:' + hostName )
	
		finally:
			scpTransport.close()
	if action == 'delete':
		try:
			os.remove(lKeytab + hostName)
		except Exception ,e:
			logging.exception('Error removing local file: ' + hostName)

def dnsUpdate(portId, ipAddr='',  action='create'):
	"""
	Update dynamic dns server A, PTR and TXT records
	on VM creation or termination.
	"""
	zone = 'osdev.skrill.net.'
	revZone = '23.32.10.in-addr.arpa'
	cname = portId + '.' + zone
	ttl = 300
	nsServer = '10.32.29.99'
        key = 'yw0ADuZjXAhcGgMOYg/Clx1128iUSfhlOHdsY4CzVNIVVVXismrAe+WKMBxocLhbrIVHGvmR94jDC46K18K6oQ=='
        keyRing = dns.tsigkeyring.from_text({zone : key})
	hostName = genHostname(ipAddr)
	dnsUpdate = dns.update.Update(zone, keyring=keyRing)
	ipAddr = str(ipAddr)
	hostName = str(hostName)
	if action == 'create':
		dnsUpdate.replace( hostName.split('.')[0], ttl, 'A', ipAddr )
		dnsResponse = dns.query.tcp(dnsUpdate, nsServer )
		logging.info('DNS A record updated for: ' + hostName)
		dnsUpdate.replace(portId, ttl, 'CNAME', hostName)
		dnsResponse = dns.query.tcp(dnsUpdate, nsServer )
		logging.info('DNS CNAME record updated for: ' + hostName)
		dnsUpdate = dns.update.Update(revZone, keyring=keyRing)
		dnsUpdate.replace(ipAddr.split('.')[3], ttl, 'PTR', hostName)
		dnsResponse = dns.query.tcp(dnsUpdate, nsServer )
		logging.info('DNS PTR record updated for: ' + hostName)
	if action == 'delete':
		try:
			hostName = dns.resolver.query(cname, 'CNAME')[0].to_text()
			ipAddr = dns.resolver.query(hostName, 'A')[0].to_text()
		except Exception, e:
			logging.exception('DNS query failed for cname and A records: ' + cname + ' ' + hostName)
			hostName = ''
			return hostName
		dnsUpdate.delete(cname, 'CNAME')
		dnsResponse = dns.query.tcp(dnsUpdate, nsServer )
		logging.info('DNS CNAME record deleted for: ' + portId + ' to ' + hostName)
		dnsUpdate.delete(hostName.split('.')[0])
		dnsResponse = dns.query.tcp(dnsUpdate, nsServer )
		logging.info('DNS A record deleted for: ' + hostName)
		dnsUpdate = dns.update.Update(revZone, keyring=keyRing)
                dnsUpdate.delete(ipAddr.split('.')[3])
		dnsResponse = dns.query.tcp(dnsUpdate, nsServer )
		logging.info('DNS PTR record deleted for: ' + hostName)
		return hostName

def mainProv(event, portId, ipAddr=''):
	"""
	Execute other function in right order
	"""
	if event == 'create':
		hostName = genHostname(ipAddr)
		ktabUpdate(hostName,action='create')
		dnsUpdate(portId=portId, ipAddr=ipAddr, action='create')
	if event == 'destroy':
		hostName = dnsUpdate(portId, action='delete')
		ktabUpdate(hostName, action='delete')

def checkNet(net,mask,ipAddr):
	"""
	Check if ip belongs to network.
	"""
	binNet = ''
	binIPaddr = ''
	for i in net.split('.'):
		binNet += bin(int(i))[2:].zfill(8)
	for j in ipAddr.split('.'):
		binIPaddr += bin(int(j))[2:].zfill(8)
	for m in range(mask):
		if binNet[m] != binIPaddr[m]:
			return False
	return True

def msgParse(body, msg):
	"""
	Parse messages and extract needed information.
	Because DNS and KDC is updated only for specific 
	network we must filter other networks here.
	"""
	net = '10.32.23.0'
	mask = 24
	if body['event_type'] == 'port.create.end':
		# list from dict with new ips
		addIps = body['payload']['port']['fixed_ips'] 
		for i in addIps:
			if checkNet(net,mask, i['ip_address']):
				logging.info('IP to be created in the provison system: ' + i['ip_address'])
				mainProv(event='create', portId=body['payload']['port']['id'],
						ipAddr=i['ip_address'])

	if body['event_type'] == 'port.delete.end':
		logging.info('Port to be deleted in the provision system: ' + body['payload']['port_id'])
		mainProv(event='destroy',portId=body['payload']['port_id'])

	msg.ack()

def consumeMsg():
	"""
	Listen Neutron info messages for creaion or deletion of
	new ports.
	"""
	osuser  = 'osdev'
	ospass  = 'osdev'
	oshost  = '10.32.29.94'
	osport  = '5672'
	osvhost = '/openstack'
	neutronExchange = Exchange('quantum', type='topic', durable=False)
	infoQueue = Queue('exthook', exchange=neutronExchange , durable=False,
			routing_key='notifications.info')
	with Connection("".join(['amqp://', osuser, ':', ospass, '@', 
		oshost, ':',osport, '/', osvhost])) as conn:
		with conn.Consumer(infoQueue, callbacks=[msgParse]):
			while True:
				try: 
					conn.drain_events()
				except Exception, e:
					logging.exception('Draining events from AMQP stop')
					break


if __name__ == '__main__':
	#ktabUpdate ('vm-10-32-23-159.osdev.skrill.net', action='create')
	consumeMsg()
	#dnsUpdate(portId='lallaa', ipAddr='1.1.1.1',  action='create')
