from axltoolkit import UcmRisPortToolkit
from credentials import user, password, platform_user, platform_password

ucm_ip = '172.18.106.58'

axl = UcmRisPortToolkit(username=user, password=password, server_ip=ucm_ip, tls_verify=False)

selection_criteria = {
    'DeviceClass': 'Any',
    'SelectBy': 'Name',
    'MaxReturnedDevices': '1000',
    'Model': 255,
    'Status': "Any",
    'SelectItems': [
        {
            'item': [
                'SEP*',          # Replace these with the devices you want to retrieve
            ]
        }
    ]
}

result = axl.get_service().selectCmDevice(StateInfo='', CmSelectionCriteria=selection_criteria)

for node in result['SelectCmDeviceResult']['CmNodes']['item']:
    server = node['Name']
    devices = node['CmDevices']['item']

    for device in devices:
        if 'IPAddress' in device:
            if device['IPAddress'] is not None and 'item' in device['IPAddress']:
                if len(device['IPAddress']['item']) > 0:
                    print(device['IPAddress']['item'][0]['IP'] + ',' + device['Name'])


