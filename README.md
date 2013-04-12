openstack
=========

Basic per tenant services check for openstack . Tested with Folsom release.

The code is writen to be executed like a nagios check. It requests a keystone token for a given tenant and saves it encrypted 
on the local filesystem, so it may be used on next invocations of the check until it expires.

Warning and critical values for everycheck are compared to the response time of the Openstack service.
Some kind of usefull performance data is returned for every check :)

ceph
=========

Nagios check if ceph cluster health is ok. Accept warning/critical values in percentage for used space.
I/O performance data is returned.
