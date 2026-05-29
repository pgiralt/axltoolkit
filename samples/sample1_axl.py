from _env import UCM_ADDRESS, UCM_AXL_VERSION, UCM_PASSWORD, UCM_TLS_VERIFY, UCM_USERNAME

from axltoolkit import AXLClient

# Credentials and UCM address come from the ``.env`` file at the repo
# root (see ``.env.example``). Override UCM_AXL_VERSION there if your
# cluster is not on 15.0.

axl = AXLClient(
    username=UCM_USERNAME,
    password=UCM_PASSWORD,
    server_ip=UCM_ADDRESS,
    tls_verify=UCM_TLS_VERIFY,
    version=UCM_AXL_VERSION,
)


# Example of using Thick AXL to retrieve User Info
# Replace this with a valid User ID from your UCM cluster:
userid = 'jsmith'

result = axl.get_user(userid)

print(result)

userdata = result['return']['user']

print("Your name is " + userdata['firstName'])

# Example of using thin AXL to retrieve User Info.
# NOTE: ``sql_query`` sends the query string verbatim. When building
# queries from variables, use ``_sanitize_sql_value`` or the higher-level
# ``sql_get_*`` helpers — never concatenate untrusted input.

from axltoolkit.axl import _sanitize_sql_value

safe_userid = _sanitize_sql_value(userid)
query = f"select * from enduser where userid = '{safe_userid}'"
result = axl.sql_query(query)
print(result)

result = axl.list_phones(name='CSF%')
print(result)
