openstack
=========

Basic services check for openstack . Tested with Folsom release.

The code is writen to be executed like a nagios check. It requests a keystone token for a given tenant and saves it encrypted 
on the local filesystem, so it may be used on next invocations of the check until it expires.
