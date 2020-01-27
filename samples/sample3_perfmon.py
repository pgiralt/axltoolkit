from axltoolkit import UcmPerfMonToolkit
from credentials import user, password, platform_user, platform_password

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