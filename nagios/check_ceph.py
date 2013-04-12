#!/usr/bin/python

import subprocess, pynagios ,re

class CheckCeph(pynagios.Plugin):

	def check(self):
		
		try:
       			cephProc = subprocess.Popen(['/usr/bin/ceph', '-s'],
                                                shell = False,
                                                stderr = subprocess.PIPE,
                                                stdout = subprocess.PIPE)
			cephStdout , cephStderr = cephProc.communicate()
		except OSError as detail:
			return pynagios.Response(pynagios.CRITICAL, "Check failed, check path: %s" % detail )
		except ValueError as detail:
			return pynagios.Response(pynagios.CRITICAL, "Check failed, check Popen parameters: %s" % detail )
		except CalledProcessError as detail:
			return pynagios.Response(pynagios.CRITICAL, "Check failed, ceph exited with error: %s" % detail )
	
		if cephStderr:
			return pynagios.Response(pynagios.CRITICAL, "Check failed: %s" % cephStderr)

		healthStat = re.search(r'HEALTH_(\w+)', cephStdout).group(1)
		freeSpace , freeSpaceMetric, allSpace , allSpaceMetric = re.search('(\d+)\s(\w+)\s/\s(\d+)\s(\w+)\savail', cephStdout).group(1,2,3,4)	
		writeSpeed, writeMetric = re.search(r'(\d+)(\w+)/s\swr,', cephStdout).group(1,2)
		iops = re.search(r'(\d+)op/s', cephStdout).group(1)

		if healthStat != 'OK':
			return pynagios.Response(pynagios.CRITICAL, "Ceph cluster degraded, status is: %s" % healthStat )
		
		# Always return write spedd in KB/s
		writeSpeed = int(writeSpeed)
		if writeMetric == 'B':
			writeSpeed = writeSpeed / 1024
		elif writeMetric == 'MB':
			writeSpeed = writeSpeed * 1024
		elif writeMetric == 'GB':
			writeSpeed = writeSpeed * 1024 * 1024
		
		# Return what percentage of the cluster space is used
		freeSpace , allSpace = float(freeSpace) , float(allSpace)
		if freeSpaceMetric == allSpaceMetric:
			usedSpacePct = round(100 - (freeSpace / allSpace) * 100)
		else:
			 raise ValueError('free/all space metrics do not match')

		resp = self.response_for_value(usedSpacePct, "%d percents used space" % usedSpacePct)
        	resp.set_perf_data("writeSpeed", int(writeSpeed), 'KB')
        	resp.set_perf_data("iops", int(iops))
        	return resp

if __name__ == '__main__':
	CheckCeph().check().exit()
