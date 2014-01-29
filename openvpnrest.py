#!/usr/bin/env python

import tornado.ioloop
import tornado.options
import tornado.web
import subprocess
import yaml
import logging
import os
 
from tornado.options import define, options
define("port", default=8080, help="change the running port", type=int)

logging.basicConfig(filename='/var/log/openvpn_restapi.log', level=logging.INFO,
                        format='%(asctime)s %(message)s')

def addDelData(action, newData):
    """
    Add/remove records from the clients.yaml file. The clients.yaml represents in YAML serialize
    a dictionary with keys clients CN and values arrays from the clients VM's ip addresses.
    Example:
    commonName: [ipaddr1, .. , ipaddrN]
    """
    with open('/root/clients.yaml','r') as dataFile:
        curData = yaml.load(dataFile)
    if not curData:
        curData = {}                 
    if action == "add":                    
        for key in newData:
            curData[key] = newData[key]
            logging.info('Added YAML record for ' + key)
    elif action == "del":
        try:
            for key in newData:
                del curData[key]
                logging.info('Deleted YAML record for ' + key)
        except KeyError:
            logging.error('No client CN to delete YAML record' + key)
    with open('/root/clients.yaml','w') as dataFile:
        yaml.dump(curData,dataFile)
    return newData.keys()

def addDelCcd(action, newData):
    """
    Add/remove CCD files per clients. Each CCD have only routes to the client's VMs pushed 
    to the client's routing table. Existing files are override.
    """
    ccdDir = '/etc/openvpn/ccd/'
    if action == 'add':
        for cName in newData:
            ccdPath = ccdDir + cName
            with open(ccdPath, 'w') as ccdFile:
                for ipAddr in newData[cName]:
                        ccdFile.write('push "route {0} 255.255.255.255 vpn_gateway"\n'.format(ipAddr))
            logging.info('Created CCD file ' + ccdPath)
    elif action == 'del':
        for cName in newData:
            ccdPath = ccdDir + cName
            try:
                os.remove(ccdPath)
                logging.info('Deleted CCD file ' + ccdPath)
            except OSError:
                logging.error('No client CCD file with path ' + ccdPath)
    return newData.keys()
    
def addDelCert(action, newData):
    """
    Add/revoke client certificate.
    """
    vpnEnv={
        'EASY_RSA':           "/etc/openvpn/easy-rsa",
        'OPENSSL':            "openssl",
        'GREP':               "grep",
        'KEY_CONFIG':         "/etc/openvpn/easy-rsa/openssl.cnf",
        'KEY_DIR':            "/etc/openvpn/easy-rsa/keys",
        'KEY_SIZE':           "2048",
        'CA_EXPIRE':          "3650",
        'KEY_EXPIRE':         "3650",
        'KEY_COUNTRY':        "BG",
        'KEY_PROVINCE':       "SF",
        'KEY_CITY':           "Sofia",
        'KEY_ORG':            "Telerik",
        'KEY_EMAIL':          "admin@telerik.com",
        'KEY_OU':             'IT'
    }
    if action == 'add':
        for cName in newData:
            cmd = ['/etc/openvpn/easy-rsa/pkitool', cName]
            try:
                pkiCmd = subprocess.Popen(cmd ,
                                  env = vpnEnv,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
                pkiOut, pkiErr = pkiCmd.communicate()
                print pkiErr,pkiOut
            except Exception as detail:
                logging.exception('Error with PKITOOL ')
            logging.info('Created certificates for ' + cName)
    elif action == 'del':
        for cName in newData:
            cmd = ['/etc/openvpn/easy-rsa/revoke-full',cName]
            os.remove('/etc/openvpn/easy-rsa/keys/' + cName + '.csr')
            os.remove('/etc/openvpn/easy-rsa/keys/' + cName + '.crt')
            os.remove('/etc/openvpn/easy-rsa/keys/' + cName + '.key')
            try:
                pkiCmd = subprocess.Popen(cmd,
                                env = vpnEnv,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
                pkiOut, pkiErr = pkiCmd.communicate()
            except Exception as detail:
                logging.exception('Error with REVOKE ')
            logging.info('Deleted certificates from store and revoked it for ' + cName)

def addDelProfile(action, data):
    """
    Generate the ovpn profile with needed certificates in it.
    Put it at download directory.
    """
    template = '/etc/openvpn/template.ovpn'
    profileDir = '/etc/openvpn/profiles/'
    keyStore = '/etc/openvpn/easy-rsa/keys/'
    if action == 'add':
        for cName in data:
            certFile = keyStore + cName + '.crt'
            keyFile = keyStore + cName + '.key'
            profileFile = profileDir + cName + '.ovpn'
            with open(template, 'r') as t:
                with open(profileFile, 'w') as p:
                    for line in t.readlines():
                        if '<cert>' in line:
                            p.write(line)
                            with open(certFile, 'r') as c:
                                binLock = 0
                                for cLine in c.readlines():
                                    if 'BEGIN CERTIFICATE' in cLine:
                                        binLock = 1
                                    if binLock:
                                        p.write(cLine)
                        elif '<key>' in line:
                            p.write(line)
                            with open(keyFile, 'r') as k:
                                p.writelines(k.readlines())
                        else:
                            p.write(line)
            logging.info('Openvpn profile file create for ' + cName)
    elif action == 'del':
        for cName in data:
            os.remove(profileDir + cName + '.ovpn')
            logging.info('Openvpn profile file deleted for ' + cName)

class AddClientVPN(tornado.web.RequestHandler):
    def post(self):
        self.data = yaml.load(self.request.body)
        for key in self.data:
            assert isinstance(self.data[key], (list, tuple)), "We need list of ip addresses"
        addDelCcd('add', self.data)
        addDelData('add', self.data)
        addDelCert('add', self.data)
        addDelProfile('add', self.data)
        self.set_header("Content-Type", "text/plain")
        self.write( ' '.join(self.data.keys()) + ' added. May the force be with you!')
        logging.info('Adding completed for ' + ' '.join(self.data.keys()))
    def write_error(self, status_code, **kwargs):
        self.write("You fail! %d error." % status_code)
        logging.error("Could not add " + ' '.join(self.data.keys()) )

class DelClientVPN(tornado.web.RequestHandler):
    def post(self):
        self.data = yaml.load(self.request.body)
        addDelCcd('del', self.data)
        addDelData('del', self.data)
        addDelCert('del', self.data)
        addDelProfile('del', self.data)
        self.set_header("Content-Type", "text/plain")
        self.write( ' '.join(self.data.keys()) + ' deleted. May the force be with you!')
        logging.info('Deleting completed for ' + ' '.join(self.data.keys()))
    def write_error(self, status_code, **kwargs):
        self.write("You fail! %d error." % status_code)
        logging.error("Could not delete " + ' '.join(self.data.keys()))

app = tornado.web.Application(handlers=[(r"/addclientvpn", AddClientVPN),
                                        (r"/delclientvpn", DelClientVPN),
                                           ])

if __name__ == "__main__":
    tornado.options.parse_command_line()
    app.listen(options.port)	
    tornado.ioloop.IOLoop.instance().start()
