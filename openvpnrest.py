#!/usr/bin/env python

import tornado.ioloop
import tornado.options
import tornado.web
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
    
class AddClientVPN(tornado.web.RequestHandler):
    def post(self):
        self.data = yaml.load(self.request.body)
        for key in self.data:
            assert isinstance(self.data[key], (list, tuple)), "We need list of ip addresses"
        addDelCcd('add', self.data)
        addDelData('add', self.data)
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
        self.set_header("Content-Type", "text/plain")
        self.write( ' '.join(self.data.keys()) + ' deleted. May the force be with you!')
        logging.info('Deleting completed for ' + ' '.join(self.data.keys()))
    def write_error(self, status_code, **kwargs):
        self.write("You fail! %d error." % status_code)
        logging.error("Could not delete " + ' '.join(self.data.keys()))

app = tornado.web.Application(handlers=[(r"/addclientvpn", AddClientVPN),
                                        (r"/delclientvpn", DelClientVPN)
                                           ])

if __name__ == "__main__":
    tornado.options.parse_command_line()
    app.listen(options.port)	
    tornado.ioloop.IOLoop.instance().start()
