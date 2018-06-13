from axltoolkit import AxlToolkit
from credentials import user, password, platform_user, platform_password

# Be sure to update the credentials.py file with your AXL User and Platform User credentials

# Put the IP address of your UCM Publisher
ucm_ip = '172.18.106.58'

axl = AxlToolkit(username=user, password=password, server_ip=ucm_ip, tls_verify=False, version='12.0')


# Example of using Thick AXL to retrieve User Info
# Replace this with a valid User ID from your UCM cluster:
userid = 'pgiralt'

result = axl.get_user(userid)

print(result)

userdata = result['return']['user']

print("Your name is " + userdata['firstName'])



# Example of using thin AXL to retrieve User Info:

query = "select * from enduser where userid = 'pgiralt'"
result = axl.run_sql_query(query)

print(result)
