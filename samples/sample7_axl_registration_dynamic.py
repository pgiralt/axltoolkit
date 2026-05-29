from _env import UCM_ADDRESS, UCM_AXL_VERSION, UCM_PASSWORD, UCM_TLS_VERIFY, UCM_USERNAME

from axltoolkit import AXLClient

# list_registration_dynamic() walks the DB and can take a while, so the
# default 30s UCM_TIMEOUT is bumped to 60s here.

axl = AXLClient(
    username=UCM_USERNAME,
    password=UCM_PASSWORD,
    server_ip=UCM_ADDRESS,
    tls_verify=UCM_TLS_VERIFY,
    version=UCM_AXL_VERSION,
    timeout=60,
)

result = axl.list_registration_dynamic()

if result is not None:
    for reg in result.items():
        print(reg)
