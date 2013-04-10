#!/usr/bin/python

from Crypto.Cipher import AES
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
	print resp.read()

	if resp.read():
		respDict = json.loads( resp.read() )
	else:
		respDict = {}

        if re.match(r'^2\d\d$', str(resp.status)):
                return  {
                         'httpCode'  : resp.status,
                         'httpReason': resp.reason,
                         'timeSpent' : stop - start,
			 'perfData'  : respDict
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
	result['perfData'] = {
				'tenants': len(result['perfData']['tenants'])
				}	
	return result	
#params = "notUsedInGet"	
	#tokenid = "ksksks"
	#tokenid = gettoken(force)
	#headers  = {"X-Auth-Token": tokenid,}
	#conn = httplib.HTTPConnection(apiEndpoint)
	#start = time.time()
	#conn.request("HEAD", "/v2.0/tokens/" + tokenid, params, headers)
	#resp = conn.getresponse()
	#stop = time.time()
	#if re.match(r'^2\d\d$', str(resp.status)):
#		return ({
#			 'httpCode': resp.status,
#                         'httpReason': resp.reason,
#			 'timeSpent' : stop - start,
#			 'perfData'  : {}
#			}) 
#	else:
#		raise CheckFail({
#				 'httpCode': resp.status,
#				 'httpReason': resp.reason
#				})
		

def checkNova(apiEndpoint):

	params = "notUsedInGet"
        tokenid = gettoken(force)
	headers = {"X-Auth-Token": tokenid,}
	conn = httplib.HTTPConnection(apiEndpoint)
        start = time.time()
        conn.request("GET", "/v2/" + tenantid + "/servers", params, headers)
        resp = conn.getresponse()
	respDict = json.loads(resp.read())
	stop = time.time()
	if re.match(r'^2\d\d$', str(resp.status)):
                return ({
			 'httpCode': resp.status,
                         'httpReason': resp.reason,
                         'timeSpent' : stop - start,
                         'perfData'  : {
					'instances' : len(respDict['servers']) 
					} 
			})
        else:
                raise CheckFail({
				 'httpCode': resp.status,
                                 'httpReason': resp.reason})

	
def checkGlance():

        params = "notUsedInGet"
        tokenid = gettoken(force)
        headers = {"X-Auth-Token": tokenid,}
        conn = httplib.HTTPConnection(apiEndpoint)
        start = time.time()
        conn.request("GET", "/v2/" + tenantid + "/servers", params, headers)
        resp = conn.getresponse()
        respDict = json.loads(resp.read())
        stop = time.time()
        if re.match(r'^2\d\d$', str(resp.status)):
                return ({
                         'httpCode': resp.status,
                         'httpReason': resp.reason,
                         'timeSpent' : stop - start,
                         'perfData'  : {
                                        'instances' : len(respDict['servers'])
                                        }
                        })
        else:
                raise CheckFail({
                                 'httpCode': resp.status,
                                 'httpReason': resp.reason})
def checkCinder():
	pass

def checkQuantum():
	pass

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
				help="Openstack admin API used for rquesting a token")
	
	parseGroup = parseArgs.add_mutually_exclusive_group(required=True)
	parseGroup.add_argument("--check-keystone", action="store_true", help="Check Keystone API by validating or requesitng a tokenid.")
	parseGroup.add_argument("--check-nova", metavar="<ip address>:<port>" ,type=str, help="Check Nova service by listing all deployed instances in the tenant. Number of instances is returned as performance data.")
	parseGroup.add_argument("--check-glance", metavar="<ip address>:<port>", type=str, help="Check Glance service by listing  uploaded images in the tenant. NUmber of images is returned as performance data.")
	parseGroup.add_argument("--check-cinder", metavar="<ip address>:<port>", type=str, help="Check Cinder service by listing created volumes in the tenant. Number of Volumes is returned as performance data.")
	parseGroup.add_argument("--check-quantum",metavar="<ip address>:<port>", type=str, help="Check Quantum service by listing all porst in the tenant. Number of ports is returned as performance data.")
	
	myargs , nagiosargs  = parseArgs.parse_known_args()

	username  = myargs.username
	password  = myargs.password
	tenantid  = myargs.tenantid

	if myargs.force_newtoken:
		force = True
	tokenurl = myargs.keystone_api

	if myargs.check_keystone:
		checkFunc = checkKeystone
		apiEndpoint = tokenurl
	elif myargs.check_nova:
		checkFunc = checkNova
		apiEndpoint = myargs.check_nova
	elif myargs.check_glance:   
                checkFunc = checkGlance
		apiEndpoint = myargs.check_glance
	elif myargs.check_cinder:   
                checkFunc = checkCinder
		apiEndpoint = myargs.check_cinder
	elif myargs.check_quantum:   
                checkFunc = checkQuantum	
		apiEndpoint = myargs.check_quantum
	

        aespass   = 'Bira$Vurst'
        tokenfile = '/tmp/ostokenfile_' + username + '_' + tenantid
        force     = False

	CheckOut(args = nagiosargs).check(checkFunc, apiEndpoint).exit()
