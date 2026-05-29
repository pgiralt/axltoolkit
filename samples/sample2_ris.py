from _env import UCM_ADDRESS, UCM_PASSWORD, UCM_TLS_VERIFY, UCM_USERNAME

from axltoolkit import RISPortClient

ris = RISPortClient(
    username=UCM_USERNAME,
    password=UCM_PASSWORD,
    server_ip=UCM_ADDRESS,
    tls_verify=UCM_TLS_VERIFY,
)

# Using the new high-level API — replaces manual selectCmDevice call
result = ris.select_cm_device(
    select_items=['SEP*'],  # Replace with the devices you want to retrieve
)

for node in result['SelectCmDeviceResult']['CmNodes']['item']:
    server = node['Name']
    devices = node['CmDevices']['item']

    for device in devices:
        if 'IPAddress' in device:
            if device['IPAddress'] is not None and 'item' in device['IPAddress']:
                if len(device['IPAddress']['item']) > 0:
                    print(device['IPAddress']['item'][0]['IP'] + ',' + device['Name'])
