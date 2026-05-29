from datetime import datetime

from _env import UCM_ADDRESS, UCM_PASSWORD, UCM_TLS_VERIFY, UCM_USERNAME

from axltoolkit import WebdialerClient

wd = WebdialerClient(
    username=UCM_USERNAME,
    password=UCM_PASSWORD,
    server_ip=UCM_ADDRESS,
    tls_verify=UCM_TLS_VERIFY,
)

start = datetime.now()
num_requests = 100

for i in range(num_requests):
    print("GO")
    print(datetime.now())
    result = wd.make_call(user='jsmith', device='SEP001122334455', line='1001', destination='2001')
    print(result)
    result = wd.end_call(user='jsmith', device='SEP001122334455', line='1001')
    print(result)
    print(datetime.now())

end = datetime.now()

print(f'Time elapsed: {end - start}')
print(f'Time per request: {(end - start) / num_requests}')
