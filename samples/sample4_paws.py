from _env import UCM_ADDRESS, UCM_PLATFORM_PASSWORD, UCM_PLATFORM_USERNAME, UCM_TLS_VERIFY

from axltoolkit import PAWSClient

# PAWS requires platform/OS admin credentials (set UCM_PLATFORM_USERNAME
# and UCM_PLATFORM_PASSWORD in .env).
paws = PAWSClient(
    username=UCM_PLATFORM_USERNAME,
    password=UCM_PLATFORM_PASSWORD,
    server_ip=UCM_ADDRESS,
    tls_verify=UCM_TLS_VERIFY,
)

# Version and cluster information
print("=== Active Version ===")
print(paws.get_active_version())

print("\n=== Cluster Nodes ===")
print(paws.get_cluster_nodes())

# Hardware and platform details
print("\n=== Hardware Information ===")
print(paws.get_hardware_information())

print("\n=== Hardware Model ===")
print(paws.get_hardware_model())

print("\n=== Deployment Mode ===")
print(paws.get_deployment_mode())

# Upgrade status
print("\n=== Upgrade Stage ===")
print(paws.get_upgrade_stage())
