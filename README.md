openstack
=========

Basic services check for openstack . Tested with Folsom release.

The code is writen to be executed like a nagios check. It requests a keystone token for a given tenant and saves it encrypted 
on the local filesystem, so it may be used on next invocation of of the check without need to request tokens everytime and 
fill the keystone tables with junk data.
