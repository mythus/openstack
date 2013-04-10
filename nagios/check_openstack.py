#!/usr/bin/python

from Crypto.Cipher import AES
import socket
import pynagios, time
import random, hashlib, base64
import httplib, datetime, string
import argparse, json, sys, os, re

class CheckOut(pynagios.Plugin):
	
	"""Wrapper for the actual check , so we may return Nagios formated output	
	"""

	def check(self, checkFunc, apiEndpoint):
		try:
			result = checkFunc(apiEndpoint)
		
		except CheckFail as detail:
			return pynagios.Response(pynagios.CRITICAL, "Check failed: %s" % detail)
		except socket.error as detail:
			return pynagios.Response(pynagios.CRITICAL, "Please recheck ip addresses and ports: %s" % detail)
	
		response = self.response_for_value(result['timeSpent'], "%.3f s to do the check" %  result['timeSpent']) 	
		
		# Set performane data , if any		
		for metric , value in result['perfData'].iteritems():
			response.set_perf_data( metric, value )

		return response

class CheckFail(Exception):
	
	"""Custom exception if check failed 
	"""

	def __init__(self,msg):
		self.message = msg
	def __str__(self):
		return repr(self.message)

def newtoken():

	"""Request token from keystone 

Uses the global variables for username, password and tenantid.
Returns dictionary created from the json response by keystone.

	"""

	headers = {"Content-Type": "application/json"}
	params = json.dumps({
       		         "auth":{
       		                 "passwordCredentials":{
                        	                        "username":username,
                	                                "password":password,
                   	            	                 }, 
                       		 "tenantId":tenantid,
                        	}
           		})

	conn = httplib.HTTPConnection(tokenurl)
	try:
		conn.request("POST", "/v2.0/tokens", params, headers)
	except Exception as detail:
		print('Please re-check ip address and port number ',detail)
		sys.exit(1)
	else:
		response = conn.getresponse()
		data = response.read()
	finally:
		conn.close()

	return  json.loads(data)



def gettoken(force=False):

	"""Read token id from file or execute newtoken()

The json returned from keystone after authentication is stored 
in file with token id encrypted
On every execution the function decrypt the token id and returns
it, If it is expired, then re-authenticate and update 
the file.

	"""
	if force and os.path.isfile(tokenfile):
		os.unlink(tokenfile)
			
	key = hashlib.md5(aespass).digest() # make 128 bit , 16 bytes key , no need for IV(tokens are random)
	mode = AES.MODE_CBC
 	encryptor = AES.new(key, mode )
	decryptor = AES.new(key, mode)	
	encAes = lambda s: base64.b64encode(encryptor.encrypt(s))
	decAes = lambda c: decryptor.decrypt(base64.b64decode(c))
 	
	try:
		with open(tokenfile,'r') as tfile:
			tokenjson = json.load(tfile)	
	except  (ValueError,IOError):
		with open(tokenfile,'w') as tfile:
             		tokenjson = newtoken()
			tokenid = tokenjson['access']['token']['id']
			tokenjson['access']['token']['id'] = encAes(tokenid)
			json.dump(tokenjson,tfile)
	else:			
		timeNow = datetime.datetime.utcnow()
		tRaw = [int(i) for i in (re.findall(r'\d+',tokenjson['access']['token']['expires']))]
		tokenExpire = datetime.datetime(year=tRaw[0],month=tRaw[1],day=tRaw[2],hour=tRaw[3],minute=tRaw[4],second=tRaw[5])
		tokenValid = datetime.timedelta(seconds=1)
		if not tokenExpire - timeNow > tokenValid:
			with open(tokenfile,'w') as tfile:
                        	tokenjson = newtoken()
	                        tokenid = tokenjson['access']['token']['id']
        	                tokenjson['access']['token']['id'] = encAes(tokenid)
                        	json.dump(tokenjson,tfile)
		else:
			tokenid = decAes(tokenjson['access']['token']['id'])

	return tokenid

def checkRestApi(apiEndpoint, url, httpReq):
	
	
        params = "notUsedInGet"
        tokenid = gettoken(force)
        headers  = {"X-Auth-Token": tokenid,}
        conn = httplib.HTTPConnection(apiEndpoint)
        start = time.time()
        conn.request( httpReq, url, params, headers )
        resp = conn.getresponse()
        stop = time.time()

	try: 
		respDict = json.loads( resp.read() )
	except ValueError:
		respDict = {}

        if re.match(r'^2\d\d$', str(resp.status)):
                return  {
                         'httpCode'  : resp.status,
                         'httpReason': resp.reason,
                         'timeSpent' : stop - start,
			 'response'  : respDict
                         }
        else:
                raise CheckFail({
                                 'httpCode': resp.status,
                                 'httpReason': resp.reason
                                })


def checkKeystone(apiEndpoint):
	
	"""Check if keystone admin API is resposive.

Recheck token validity

	"""
	
	url = "/v2.0/tenants"
	httpReq = "GET"

	result = checkRestApi(apiEndpoint, url, httpReq)
	perfData = result['response']
	print perfData
	result['perfData'] = {
				'tenants': len(perfData['tenants'])
				}	
	return result	

def checkNova(apiEndpoint):

        url = "/v2/" + tenantid + "/servers"
	httpReq = "GET"
	
	result = checkRestApi( apiEndpoint, url, httpReq )
	perfData = result['response']
	result['perfData'] = {
				'instances' : len(perfData['servers'])
				}

	return result
	
def checkGlance(apiEndpoint):

	url = "/v2/images"
        httpReq = "GET"

        result = checkRestApi( apiEndpoint, url, httpReq )
        perfData = result['response']
        result['perfData'] = {
                                'images' : len(perfData['images'])
                                }

        return result

def checkCinder(apiEndpoint):
	
	url = "/v1/" + tenantid + "/volumes"
        httpReq = "GET"

        result = checkRestApi( apiEndpoint, url, httpReq )
        perfData = result['response']
	volsAttached = 0
	for i in perfData['volumes']:
		if not len(i['attachments']) == 0:
			volsAttached += 1
		
        result['perfData'] = {
                                'vols' : len(perfData['volumes']),
				'volsAttached' : volsAttached
                                }

        return result

def checkQuantum(apiEndpoint):
	
        httpReq = "GET"

	url = "/v2.0/networks"
	result = checkRestApi( apiEndpoint, url, httpReq )
        perfDataNets = checkRestApi( apiEndpoint, url, httpReq )['response']
	timeSpentNets = result['timeSpent']
        
	url = "/v2.0/subnets"
	result = checkRestApi( apiEndpoint, url, httpReq )
	perfDataSubnets = result['response']
	timeSpentSubnets = result['timeSpent']

	url = "/v2.0/ports"
        result = checkRestApi( apiEndpoint, url, httpReq )
       
	 
	perfData = result['response']
	result['timeSpent'] += timeSpentNets + timeSpentSubnets
        result['perfData'] = {
				'networks' : len(perfDataNets['networks']),
				'subnets'  : len(perfDataSubnets['subnets']),
                                'ports'    : len(perfData['ports'])
                                }

        return result

if __name__ == '__main__':
	

	parseArgs = argparse.ArgumentParser(description='Basic OpenStack checks', epilog="Have fun :)", prog="check_openstack")
	parseArgs.add_argument("-v","--version", action='version', version='%(prog)s 0.1b')
	parseArgs.add_argument("-u", "--username", type=str, help="Openstack username", required=True)
        parseArgs.add_argument("-p", "--password", type=str, help="Openstack password", required=True)
        parseArgs.add_argument("-t", "--tenantid", type=str, help="Openstack tenantid", required=True)
        parseArgs.add_argument("-f", "--force-newtoken", action="store_true", 
				help="""force re-authentication and generation of new token. By default new token is requested 
                                   at script start and saved encrypted in the /tmp/ostokenfile to be used until it expires""")
        parseArgs.add_argument("--keystone-api", metavar="<ip address>:<port>", type=str, required=True,
				help="Openstack admin API used for rquesting a token. If port not specified default 5000 is used.")
	
	parseGroup = parseArgs.add_mutually_exclusive_group(required=True)
	parseGroup.add_argument("--check-keystone", action="store_true", help="Check Keystone API by validating or requesitng a tokenid.")
	parseGroup.add_argument("--check-nova", metavar="<ip address>:<port>" ,type=str, help="Check Nova service by listing all deployed instances in the tenant. Number of instances is returned as performance data. If port not specified default 8774 is used.")
	parseGroup.add_argument("--check-glance", metavar="<ip address>:<port>", type=str, help="Check Glance service by listing  uploaded images in the tenant. NUmber of images is returned as performance data. If port not specified default 9292 is used.")
	parseGroup.add_argument("--check-cinder", metavar="<ip address>:<port>", type=str, help="Check Cinder service by listing created volumes in the tenant. Number of Volumes is returned as performance data. If port not specified default 8776 is used.")
	parseGroup.add_argument("--check-quantum",metavar="<ip address>:<port>", type=str, help="Check Quantum service by listing all porst in the tenant. Number of net, subnets and ports are returned as performance data. If port not specified default 9696 is used.")
	
	myargs , nagiosargs  = parseArgs.parse_known_args()

	username  = myargs.username
	password  = myargs.password
	tenantid  = myargs.tenantid

	if myargs.force_newtoken:
		force = True

	if re.search(r':', myargs.keystone_api):
		tokenurl = myargs.keystone_api
	else:
		tokenurl = myargs.keystone_api + ':5000'
	
	# Mutually exclusive services
	if myargs.check_keystone:
		checkFunc = checkKeystone
		apiEndpoint = tokenurl

	elif myargs.check_nova:
		checkFunc = checkNova
		if re.search(r':', myargs.check_nova):
			apiEndpoint = myargs.check_nova
		else:
			apiEndpoint = myargs.check_nova + ':8774'

	elif myargs.check_glance:   
                checkFunc = checkGlance
                if re.search(r':', myargs.check_glance):
                        apiEndpoint = myargs.check_glance
                else:
                        apiEndpoint = myargs.check_glance + ':9292'

	elif myargs.check_cinder:   
                checkFunc = checkCinder
                if re.search(r':', myargs.check_cinder):
                        apiEndpoint = myargs.check_cinder
                else:
                        apiEndpoint = myargs.check_cinder + ':8776'

	elif myargs.check_quantum:   
                checkFunc = checkQuantum	
                if re.search(r':', myargs.check_quantum):
                        apiEndpoint = myargs.check_quantum
                else:
                        apiEndpoint = myargs.check_quantum + ':9696'

        aespass   = 'Bira$Vurst'
        tokenfile = '/tmp/ostokenfile_' + username + '_' + tenantid
        force     = False

	CheckOut(args = nagiosargs).check(checkFunc, apiEndpoint).exit()
