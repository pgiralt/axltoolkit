from axltoolkit import PawsToolkit
from credentials import user, password, platform_user, platform_password

ucm_ip = '172.18.106.58'

paws = PawsToolkit(platform_user, platform_password, ucm_ip, 'VersionService', False)

result = paws.get_active_version()

print(result)

