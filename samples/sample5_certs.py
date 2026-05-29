# This sample reads the UCM certificate table via Thin AXL and decodes
# each certificate's subject + ``notAfter`` date for inventory purposes.
#
# Requires ``asn1crypto`` for X.509 parsing (not a runtime dep of
# axltoolkit itself — install separately):
#
#     pip install asn1crypto
#
from pprint import pprint

from _env import UCM_ADDRESS, UCM_AXL_VERSION, UCM_PASSWORD, UCM_TLS_VERIFY, UCM_USERNAME
from asn1crypto import pem, x509

from axltoolkit import AXLClient


def subject_to_string(subject):
    subject_string = ''

    for value, key in subject.items():
        if subject_string != '':
            subject_string += ', '

        subject_string += value + ' = ' + str(key)

    return subject_string


axl = AXLClient(
    username=UCM_USERNAME,
    password=UCM_PASSWORD,
    server_ip=UCM_ADDRESS,
    tls_verify=UCM_TLS_VERIFY,
    version=UCM_AXL_VERSION,
)

query = 'select * from certificate'

result = axl.sql_query(query)

for row in result['rows']:

    cert = str.encode(row['certificate'], 'utf-8')

    if pem.detect(cert):
        cert_type, cert_headers, der_bytes = pem.unarmor(cert)

        cert_data = x509.Certificate.load(der_bytes)['tbs_certificate'].native

        not_before = cert_data['validity']['not_before']
        not_after = cert_data['validity']['not_after']

        print('"' + subject_to_string(cert_data['subject']) + '",' + str(not_after))

        pprint(dict(cert_data.items()))
