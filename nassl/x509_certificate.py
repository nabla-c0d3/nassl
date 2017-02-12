# -*- coding: utf-8 -*-
import base64
import hashlib
from binascii import hexlify
import re
from nassl._nassl import X509

from enum import Enum
from typing import Dict
from typing import Text


class HostnameValidationResultEnum(Enum):
    """Hostname validation result constants.
    """
    NAME_DOES_NOT_MATCH = 0
    NAME_MATCHES_SAN = 1
    NAME_MATCHES_CN = 2


class X509HostnameValidationError(ValueError):
    pass


class X509Certificate(object):
    """High level API for parsing an X509 certificate.
    """

    def __init__(self, x509):
        # type: (X509) -> None
        self._cert_dict = None
        self._x509 = x509


    @classmethod
    def from_pem(cls, pem_certificate):
        # type: (Text) -> X509Certificate
        """Create an X509Certificate object from a PEM-formatted certificate.
        """
        x509 = X509(pem_certificate)
        return cls(x509)


    def as_text(self):
        # type: () -> Text
        return self._x509.as_text()


    def as_pem(self):
        # type: () -> Text
        return self._x509.as_pem()


    def get_SHA1_fingerprint(self):
        # type: () -> Text
        return hexlify(self._x509.digest())


    def get_hpkp_pin(self):
        # type: () -> Text
        """Return the SHA-256 of the Subject Public Key Info base64-encoded, to be used for HTTP Public Key Pinning.
        """
        spki_bytes = self._x509.get_spki_bytes()
        hashed_bytes = hashlib.sha256(spki_bytes).digest()
        return base64.b64encode(hashed_bytes)


    def as_dict(self):
        # type: () -> Dict
        if self._cert_dict:
            return self._cert_dict

        cert_dict = {u'version': self._x509.get_version(),
                     u'serialNumber': self._x509.get_serialNumber(),
                     u'issuer': self._parse_x509_name(self._x509.get_issuer_name_entries()),
                     u'validity': {
                         u'notBefore': self._x509.get_notBefore(),
                         u'notAfter': self._x509.get_notAfter()
                     },
                     u'subject': self._parse_x509_name(self._x509.get_subject_name_entries()),
                     u'subjectPublicKeyInfo': self._parse_pubkey(),
                     u'extensions': self._parse_x509_extensions(),
                     u'signatureAlgorithm': self._parse_signature_algorithm(),
                     u'signatureValue': self._parse_signature()}
        self._cert_dict = cert_dict
        return cert_dict


    def matches_hostname(self, hostname):
        # type: (Text) -> HostnameValidationResultEnum

        """Attempt to match the given hostname with the name(s) the certificate was issued to.

        Will raise X509HostnameValidationError if the certificate is malformed.
        """
        cert_dict = self.as_dict()

        # First look at Subject Alternative Names
        try:
            subject_alt_names = cert_dict[u'extensions'][u'X509v3 Subject Alternative Name'][u'DNS']
            for altname in subject_alt_names:
                if self._dnsname_match(altname, hostname):
                    return HostnameValidationResultEnum.NAME_MATCHES_SAN
            return HostnameValidationResultEnum.NAME_DOES_NOT_MATCH

        except KeyError: # No SAN in this cert; try the Common Name
            pass

        try:
            common_name = cert_dict[u'subject'][u'commonName']
            if self._dnsname_match(common_name, hostname):
                return HostnameValidationResultEnum.NAME_MATCHES_CN
        except KeyError: # No CN either ? This certificate is malformed
            raise X509HostnameValidationError(u'Certificate has no subjectAltName and no Common Name; '
                                              u'malformed certificate ?')

        return HostnameValidationResultEnum.NAME_DOES_NOT_MATCH



# "Private" methods

# Hostname validation
    @staticmethod
    def _dnsname_match(dn, hostname, max_wildcards=1):
        """
        Taken from https://bitbucket.org/brandon/backports.ssl_match_hostname/
        """
        pats = []
        if not dn:
            return False

        # Ported from python3-syntax:
        # leftmost, *remainder = dn.split(r'.')
        parts = dn.split(r'.')
        leftmost = parts[0]
        remainder = parts[1:]

        wildcards = leftmost.count('*')
        if wildcards > max_wildcards:
            # Issue #17980: avoid denials of service by refusing more
            # than one wildcard per fragment.  A survey of established
            # policy among SSL implementations showed it to be a
            # reasonable choice.
            raise X509HostnameValidationError(u'too many wildcards in certificate DNS name: {}'.format(repr(dn)))

        # speed up common case w/o wildcards
        if not wildcards:
            return dn.lower() == hostname.lower()

        # RFC 6125, section 6.4.3, subitem 1.
        # The client SHOULD NOT attempt to match a presented identifier in which
        # the wildcard character comprises a label other than the left-most label.
        if leftmost == '*':
            # When '*' is a fragment by itself, it matches a non-empty dotless
            # fragment.
            pats.append('[^.]+')
        elif leftmost.startswith('xn--') or hostname.startswith('xn--'):
            # RFC 6125, section 6.4.3, subitem 3.
            # The client SHOULD NOT attempt to match a presented identifier
            # where the wildcard character is embedded within an A-label or
            # U-label of an internationalized domain name.
            pats.append(re.escape(leftmost))
        else:
            # Otherwise, '*' matches any dotless string, e.g. www*
            pats.append(re.escape(leftmost).replace(r'\*', '[^.]*'))

        # add the remaining fragments, ignore any wildcards
        for frag in remainder:
            pats.append(re.escape(frag))

        pat = re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)
        return pat.match(hostname)



# Value extraction
    def _extract_cert_value(self, key):
        certValue = self.as_text().split(key)
        return certValue[1].split('\n')[0].strip()


    def _parse_signature_algorithm(self):
        return self._extract_cert_value('Signature Algorithm: ')


    def _parse_signature(self):
        cert_txt = self.as_text()
        sig_txt = cert_txt.split('Signature Algorithm:', 1)[1].split('Signature Algorithm:')[1].split('\n',1)[1]
        sig_parts = sig_txt.split('\n')
        signature = ''
        for part in sig_parts:
            signature += part.strip()
        return signature.strip()


    @staticmethod
    def _parse_x509_name(name_entries):
        name_entries_dict = {}
        for entry in name_entries:
            name_entries_dict[entry.get_object()] = entry.get_data()
        return name_entries_dict


# Public Key Parsing Functions
# The easiest and ugliest way to do this is to just parse OpenSSL's text output
# I don't want to create an EVP_PKEY class in C just for this
# Of course lots of assumptions here regarding the format of the text output

    def _parse_pubkey(self):
        algo = self._parse_pubkey_algorithm()
        if algo in [u'id-ecPublicKey', u'id-ecDH', u'id-ecMQV']:
            paramDict = {u'pub': self._parse_ec_pubkey(),
                         u'curve': self._parse_ec_pubkey_curve() }
        else: # RSA, DSA
            paramDict = {u'modulus': self._parse_pubkey_modulus(),
                         u'exponent': self._parse_pubkey_exponent() }

        pubkeyDict = {
            u'publicKeyAlgorithm': algo ,
            u'publicKeySize': str( self._parse_pubkey_size()) ,
            u'publicKey': paramDict }
        return pubkeyDict


    def _parse_ec_pubkey(self):
        cert =  self.as_text()
        eckey_lines = cert.split('pub:')[1].split('\n', 1)[1].split('ASN1 OID:')[0].strip().split('\n')
        pubkey_txt = ''

        for line in eckey_lines:
            pubkey_txt += line.strip()
        return pubkey_txt


    def _parse_ec_pubkey_curve(self):
        exp = self._extract_cert_value('ASN1 OID:')
        return exp.split('(')[0].strip()


    def _parse_pubkey_modulus(self):
        cert =  self.as_text()
        modulus_lines = cert.split('Modulus')[1].split('\n',1)[1].split('Exponent:')[0].strip().split('\n')
        pubkey_modulus_txt = ''

        for line in modulus_lines:
            pubkey_modulus_txt += line.strip()
        return pubkey_modulus_txt


    def _parse_pubkey_exponent(self):
        exp = self._extract_cert_value('Exponent:')
        return exp.split('(')[0].strip()


    def _parse_pubkey_size(self):
        exp = self._extract_cert_value('Public-Key: ')
        return exp.strip(' ()')


    def _parse_pubkey_algorithm(self):
        return self._extract_cert_value('Public Key Algorithm: ')



# Extension Parsing Functions
    def _parse_x509_extensions(self):
        x509_ext_parsing_methods = {
            u'X509v3 Subject Alternative Name': self._parse_san,
            u'X509v3 CRL Distribution Points': self._parse_crl_distribution_points,
            u'Authority Information Access': self._parse_authority_information_access,
            u'X509v3 Key Usage': self._parse_multi_valued_extension,
            u'X509v3 Extended Key Usage': self._parse_multi_valued_extension,
            u'X509v3 Certificate Policies': self._parse_crl_distribution_points,
            u'X509v3 Issuer Alternative Name': self._parse_crl_distribution_points,
            u'X509v3 Basic Constraints': self._parse_multi_valued_extension
        }

        ext_dict = {}

        for x509ext in self._x509.get_extensions():
            ext_name = x509ext.get_object()
            # TODO: Should we output the critical field ?
            #extCrit = x509ext.get_critical()
            if ext_name in x509_ext_parsing_methods.keys():
                ext_dict[ext_name] = x509_ext_parsing_methods[ext_name](x509ext)
            else:
                ext_dict[ext_name] = x509ext.get_data().strip()

        return ext_dict



    @staticmethod
    def _parse_san(extension):
        return extension.parse_subject_alt_name()


    @staticmethod
    def _parse_multi_valued_extension(x509ext):
        extension = x509ext.get_data().split(', ')
        # Split the (key,value) pairs
        parsed_ext = {}
        for value in extension:
            value = value.split(':', 1)
            if len(value) == 1:
                parsed_ext[value[0]] = ''
            else:
                if parsed_ext.has_key(value[0]):
                    parsed_ext[value[0]].append(value[1])
                else:
                    parsed_ext[value[0]] = [value[1]]

        return parsed_ext


    @staticmethod
    def _parse_authority_information_access(x509ext):
        # Hazardous attempt at parsing an Authority Information Access extension
        auth_ext = x509ext.get_data().strip(' \n').split('\n')
        auth_ext_list = {}

        for auth_entry in auth_ext:
            auth_entry = auth_entry.split(' - ')
            entry_name = auth_entry[0].replace(' ', '')

            if not auth_ext_list.has_key(entry_name):
                auth_ext_list[entry_name] = {}

            entry_data = auth_entry[1].split(':', 1)
            if auth_ext_list[entry_name].has_key(entry_data[0]):
                auth_ext_list[entry_name][entry_data[0]].append(entry_data[1])
            else:
                auth_ext_list[entry_name] = {entry_data[0]: [entry_data[1]]}

        return auth_ext_list


    @staticmethod
    def _parse_crl_distribution_points(x509ext):
        # Hazardous attempt at parsing a CRL Distribution Point extension
        crl_ext = x509ext.get_data().strip(' \n').split('\n')
        subcrl = {}

        for distrib_point in crl_ext:
            distrib_point = distrib_point.strip()
            distrib_point = distrib_point.split(':', 1)
            if len(distrib_point) >= 2:
                if subcrl.has_key(distrib_point[0].strip()):
                    subcrl[distrib_point[0].strip()].append(distrib_point[1].strip())
                else:
                    subcrl[distrib_point[0].strip()] = [(distrib_point[1].strip())]

        return subcrl

