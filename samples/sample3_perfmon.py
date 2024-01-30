from axltoolkit import UcmPerfMonToolkit
from credentials import user, password

ucm_ip = '172.18.106.58'

axl = UcmPerfMonToolkit(user, password, ucm_ip, False)

session_handle = axl.perfmonOpenSession()

counters = [
    "\\\\vnt-cm1b.cisco.com\\Cisco Locations LBM(BranchRemote->Hub_None)\\BandwidthAvailable",
    "\\\\vnt-cm1b.cisco.com\\Cisco Locations LBM(BranchRemote->Hub_None)\\BandwidthMaximum",
    "\\\\vnt-cm1b.cisco.com\\Cisco Locations LBM(BranchRemote->Hub_None)\\CallsInProgress",
    "\\\\vnt-cm1b.cisco.com\\Cisco Locations LBM(Hub_None)\\CallsInProgress",
    "\\\\vnt-cm1b.cisco.com\\Cisco SIP(ecats-rtp-dmz-cube2)\\CallsAttempted",
    "\\\\vnt-cm1b.cisco.com\\Cisco CallManager\\CallsCompleted"
]

result = axl.perfmonAddCounter(session_handle=session_handle, counters=counters)

if result is True:
    result = axl.perfmonCollectSessionData(session_handle=session_handle)
else:
    result = "Error adding perfmon counter"

print(result)

result = axl.perfmonCloseSession(session_handle=session_handle)

# Change this to the hostnames in your cluster
hosts = ['vnt-cm1a.cisco.com', 'vnt-cm1b.cisco.com', 'vnt-cm1c.cisco.com']


counters = []
counter = 'Active'
for host in hosts:
    lines = axl.perfmonListInstance(host=host, object_name='Cisco Lines')

    for line in lines:
        counter_string = f'\\\\{host}\\({line})\\{counter}'

        counters.append(counter_string)

print(counters)
