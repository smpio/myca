import copy
import datetime
import ipaddress
import subprocess

from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CertInfo:
    def __init__(self, data=None):
        self.key_size = None
        self.key_public_exponent = None
        self.subj_cn = None
        self.subj_c = None
        self.subj_o = None
        self.subj_ou = None
        self.subj_dnq = None
        self.subj_st = None
        self.subj_sn = None
        self.cert_validate_since = None
        self.cert_validate_till = None
        self.ku_web_server_auth = None
        self.ku_web_client_auth = None
        self.san_dns_names = []
        self.san_ips = []
        self.issuer = None
        self.issuer_cn = None
        self.self_signed = None

        if data is not None:
            self.__dict__.update(data)

    def as_dict(self):
        return copy.copy(self.__dict__)


def issue_certificate(data, ca_pair=None):
    key = rsa.generate_private_key(public_exponent=data.key_public_exponent, key_size=data.key_size,
                                   backend=default_backend())
    key_id = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

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
        .add_extension(key_id, critical=False) \
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
        ca_subject = ca_cert.subject
        ca_sn = ca_cert.serial_number
    else:
        cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        ca_cert = cert
        ca_key = key
        ca_key_id = key_id
        ca_subject = subject
        ca_sn = sn

    cert = cert \
        .issuer_name(ca_subject) \
        .add_extension(x509.AuthorityKeyIdentifier(ca_key_id.digest,
                                                   [x509.DirectoryName(ca_subject)],
                                                   ca_sn),
                       critical=False) \
        .add_extension(x509.KeyUsage(digital_signature=True,
                                     content_commitment=False,
                                     key_encipherment=bool(ca_pair),
                                     data_encipherment=False,
                                     key_agreement=False,
                                     key_cert_sign=not bool(ca_pair),
                                     crl_sign=not bool(ca_pair),
                                     encipher_only=False,
                                     decipher_only=False),
                       critical=True) \
        .sign(ca_key, hashes.SHA256(), default_backend())

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


def load_certificate_info(pair, reissue=False):
    cert = x509.load_pem_x509_certificate(pair[0], default_backend())
    key = serialization.load_pem_private_key(pair[1], password=None, backend=default_backend())
    public_key = key.public_key()

    info = CertInfo()
    info.key_size = key.key_size
    info.key_public_exponent = public_key.public_numbers().e

    v = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if v:
        info.subj_cn = v[0].value
    v = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if v:
        info.subj_c = v[0].value
    v = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if v:
        info.subj_o = v[0].value
    v = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if v:
        info.subj_ou = v[0].value
    v = cert.subject.get_attributes_for_oid(NameOID.DN_QUALIFIER)
    if v:
        info.subj_dnq = v[0].value
    v = cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
    if v:
        info.subj_st = v[0].value
    v = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    if v:
        info.subj_sn = v[0].value

    v = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if v:
        info.issuer_cn = v[0].value

    info.self_signed = cert.subject == cert.issuer

    info.cert_validate_since = cert.not_valid_before
    info.cert_validate_till = cert.not_valid_after

    if reissue:
        valid_period = info.cert_validate_till - info.cert_validate_since
        info.cert_validate_since = datetime.datetime.utcnow()
        info.cert_validate_till = info.cert_validate_since + valid_period

    try:
        ext_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.extensions.ExtensionNotFound:
        pass
    else:
        info.ku_web_server_auth = ExtendedKeyUsageOID.SERVER_AUTH in ext_key_usage
        info.ku_web_client_auth = ExtendedKeyUsageOID.CLIENT_AUTH in ext_key_usage

    try:
        alt_names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.extensions.ExtensionNotFound:
        pass
    else:
        info.san_dns_names = alt_names.get_values_for_type(x509.DNSName)
        info.san_ips = [str(ip) for ip in alt_names.get_values_for_type(x509.IPAddress)]

    return info


def verify_certificate_chain(cert_data, ca_cert_chain_data=()):
    try:
        store = crypto.X509Store()

        for ca_cert_data in ca_cert_chain_data:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_data)
            store.add_cert(ca_cert)

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        store_ctx = crypto.X509StoreContext(store, cert)
        store_ctx.verify_certificate()
    except crypto.Error as e:
        raise InvalidCertificate('Broken certificate') from e
    except crypto.X509StoreContextError as e:
        raise InvalidCertificate('Invalid certificate chain: ' + str(e)) from e


def does_keys_match(pair):
    cert = x509.load_pem_x509_certificate(pair[0], default_backend())
    key = serialization.load_pem_private_key(pair[1], password=None, backend=default_backend())
    key1 = cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key2 = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key1 == key2


class InvalidCertificate(Exception):
    pass
