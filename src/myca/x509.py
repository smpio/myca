import ipaddress
import subprocess

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CertData:
    def __init__(self, data):
        self.__dict__.update(data)


def issue_certificate(data, ca_pair=None):
    key = rsa.generate_private_key(public_exponent=data.key_public_exponent, key_size=data.key_size,
                                   backend=default_backend())

    subj_name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, data.subj_cn)]
    if data.subj_c:
        subj_name_attrs += [x509.NameAttribute(NameOID.COUNTRY_NAME, data.subj_c)]
    if data.subj_o:
        subj_name_attrs += [x509.NameAttribute(NameOID.ORGANIZATION_NAME, data.subj_o)]
    if data.subj_ou:
        subj_name_attrs += [x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, data.subj_ou)]
    if data.subj_dnq:
        subj_name_attrs += [x509.NameAttribute(NameOID.DN_QUALIFIER, data.subj_dnq)]
    if data.subj_st:
        subj_name_attrs += [x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, data.subj_st)]
    if data.subj_sn:
        subj_name_attrs += [x509.NameAttribute(NameOID.SERIAL_NUMBER, data.subj_sn)]
    subject = x509.Name(subj_name_attrs)

    sn = x509.random_serial_number()

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(sn) \
        .not_valid_before(data.cert_validate_since) \
        .not_valid_after(data.cert_validate_till)

    extended_usages = []
    if data.ku_web_server_auth:
        extended_usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if data.ku_web_client_auth:
        extended_usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if extended_usages:
        cert = cert.add_extension(x509.ExtendedKeyUsage(extended_usages), critical=False)

    sans = [x509.DNSName(name) for name in data.san_dns_names]
    sans += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in data.san_ips]
    if sans:
        cert = cert.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    if ca_pair:
        ca_cert, ca_key = ca_pair

        ca_cert = x509.load_pem_x509_certificate(ca_cert, default_backend())
        ca_key = serialization.load_pem_private_key(ca_key, password=None, backend=default_backend())
        ca_key_id = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())

        cert = cert \
            .issuer_name(ca_cert.issuer) \
            .add_extension(x509.AuthorityKeyIdentifier(ca_key_id.digest,
                                                       [x509.DirectoryName(ca_cert.issuer)],
                                                       ca_cert.serial_number),
                           critical=False) \
            .add_extension(x509.KeyUsage(digital_signature=True,
                                         content_commitment=False,
                                         key_encipherment=True,
                                         data_encipherment=False,
                                         key_agreement=False,
                                         key_cert_sign=False,
                                         crl_sign=False,
                                         encipher_only=False,
                                         decipher_only=False),
                           critical=True) \
            .sign(ca_key, hashes.SHA256(), default_backend())
    else:
        key_id = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

        cert = cert \
            .issuer_name(subject) \
            .add_extension(key_id, critical=False) \
            .add_extension(x509.AuthorityKeyIdentifier(key_id.digest,
                                                       [x509.DirectoryName(subject)],
                                                       sn),
                           critical=False) \
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True) \
            .add_extension(x509.KeyUsage(digital_signature=True,
                                         content_commitment=False,
                                         key_encipherment=False,
                                         data_encipherment=False,
                                         key_agreement=False,
                                         key_cert_sign=True,
                                         crl_sign=True,
                                         encipher_only=False,
                                         decipher_only=False),
                           critical=True) \
            .sign(key, hashes.SHA256(), default_backend())

    cert = cert.public_bytes(serialization.Encoding.PEM)
    key = key.private_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption())
    return cert, key


def get_certificate_text(cert_data):
    return subprocess.run(['openssl', 'x509',
                           '-in', '/dev/stdin',
                           '-text'],
                          check=True,
                          stdout=subprocess.PIPE,
                          input=cert_data).stdout.decode('ascii')
