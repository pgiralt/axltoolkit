from _env import UCM_ADDRESS, UCM_PASSWORD, UCM_TLS_VERIFY, UCM_USERNAME

from axltoolkit import PerfMonClient

pm = PerfMonClient(
    username=UCM_USERNAME,
    password=UCM_PASSWORD,
    server_ip=UCM_ADDRESS,
    tls_verify=UCM_TLS_VERIFY,
)

session_handle = pm.open_session()

# PerfMon counter syntax: \\<node-fqdn>\<object>(<instance>)\<counter>
# Adjust the counter list to match what's available on your cluster —
# these are illustrative defaults that work on most UCM publishers.
counters = [
    f"\\\\{UCM_ADDRESS}\\Cisco Locations LBM(Hub_None)\\BandwidthAvailable",
    f"\\\\{UCM_ADDRESS}\\Cisco Locations LBM(Hub_None)\\BandwidthMaximum",
    f"\\\\{UCM_ADDRESS}\\Cisco Locations LBM(Hub_None)\\CallsInProgress",
    f"\\\\{UCM_ADDRESS}\\Cisco CallManager\\CallsCompleted",
]

pm.add_counters(session_handle=session_handle, counters=counters)
result = pm.collect_session_data(session_handle=session_handle)

print(result)

pm.close_session(session_handle=session_handle)

# Replace this with the hostnames in your cluster (publisher + subscribers).
# By default we only enumerate lines on the node from the .env file.
hosts = [UCM_ADDRESS]

counters = []
counter = 'Active'
for host in hosts:
    print(host)
    lines = pm.list_instances(host=host, object_name='Cisco Lines')
    print(lines)

    for line in (lines or []):
        counter_string = f'\\\\{host}\\({line})\\{counter}'

        counters.append(counter_string)

print(counters)
