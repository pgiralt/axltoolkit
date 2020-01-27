from axltoolkit import AxlToolkit
from asn1crypto import pem, x509
from pprint import pprint
from credentials import user, password


def subject_to_string(subject):
    subject_string = ''

    for value, key in subject.items():
        if subject_string != '':
            subject_string += ', '

        subject_string += value + ' = ' + str(key)

    return subject_string


ucm_ip = '172.18.106.58'

axl = AxlToolkit(username=user, password=password, server_ip=ucm_ip, tls_verify=False, version='12.5')

query = 'select * from certificate'

result = axl.run_sql_query(query)

for row in result['rows']:

    cert = str.encode(row['certificate'], 'utf-8')

    if pem.detect(cert):
        cert_type, cert_headers, der_bytes = pem.unarmor(cert)

        cert_data = x509.Certificate.load(der_bytes)['tbs_certificate'].native

        not_before = cert_data['validity']['not_before']
        not_after = cert_data['validity']['not_after']

        print('"' + subject_to_string(cert_data['subject']) + '",' + str(not_after))

        pprint(dict(cert_data.items()))