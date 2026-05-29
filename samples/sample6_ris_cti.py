from _env import UCM_ADDRESS, UCM_PASSWORD, UCM_TLS_VERIFY, UCM_USERNAME

from axltoolkit import RISPortClient

ris = RISPortClient(
    username=UCM_USERNAME,
    password=UCM_PASSWORD,
    server_ip=UCM_ADDRESS,
    tls_verify=UCM_TLS_VERIFY,
)

# Using the new high-level API — replaces manual selectCtiItem call
result = ris.select_cti_item(
    device_names=['*'],  # Replace with the devices you want to retrieve
)

print(result)
