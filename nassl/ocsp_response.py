# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from nassl import _nassl
from typing import Dict
from typing import Text

class OcspResponseNotTrustedError(IOError):

    def __init__(self, trust_store_path):
        # type: (Text) -> None
        self.trust_store_path = trust_store_path


class OcspResponse(object):
    """High level API for parsing an OCSP response.
    """

    def __init__(self, ocsp_response):
        # type: (_nassl.OCSP_RESPONSE) -> None
        self._ocsp_response = ocsp_response
        self._ocsp_response_dict = None


    def as_text(self):
        # type: () -> Text
        return self._ocsp_response.as_text()


    def verify(self, verify_locations):
        # type: (Text) -> None
        """Verify that the OCSP response is trusted.

        Args:
            verify_locations: The file path to a trust store containing pem-formatted certificates, to be used for
            validating the OCSP response.

        Raises OcspResponseNotTrustedError if the validation failed ie. the OCSP response is not trusted.
        """
        # Ensure the file exists
        with open(verify_locations):
            pass

        try:
            self._ocsp_response.basic_verify(verify_locations)
        except _nassl.OpenSSLError as e:
            if 'certificate verify error' in e[0]:
                raise OcspResponseNotTrustedError(verify_locations)
            raise


    def as_dict(self):
        # type: () -> Dict[Text, Text]
        if self._ocsp_response_dict:
            return self._ocsp_response_dict

        # For now we just parse OpenSSL's text output and make a lot of assumptions
        response_dict = {
            'responseStatus': self._get_value_from_text_output_no_p('OCSP Response Status:'),
            'version' : self._get_value_from_text_output_no_p('Version:'),
            'responseType': self._get_value_from_text_output('Response Type:'),
            'responderID': self._get_value_from_text_output('Responder Id:'),
            'producedAt': self._get_value_from_text_output('Produced At:'),
            'ctResponseScts': self._get_scts_from_text_output()
            }
        if 'successful' not in response_dict['responseStatus']:
            return response_dict

        response_dict['responses'] = [
            {
                'certID': {
                    'hashAlgorithm': self._get_value_from_text_output('Hash Algorithm:'),
                    'issuerNameHash': self._get_value_from_text_output('Issuer Name Hash:'),
                    'issuerKeyHash': self._get_value_from_text_output('Issuer Key Hash:'),
                    'serialNumber': self._get_value_from_text_output('Serial Number:')
                },
                'certStatus': self._get_value_from_text_output('Cert Status:'),
                'thisUpdate': self._get_value_from_text_output('This Update:'),
                'nextUpdate': self._get_value_from_text_output('Next Update:')
            }
        ]
        self._ocsp_response_dict = response_dict
        return response_dict


# Text parsing
    def _get_value_from_text_output(self, key):
        # type: (Text) -> Text
        value = self._ocsp_response.as_text().split(key)
        return value[1].split('\n')[0].strip()


    def _get_value_from_text_output_no_p(self, key):
        # type: (Text) -> Text
        value = self._ocsp_response.as_text().split(key)
        value = value[1].split('\n')[0].strip()
        return value.split('(')[0].strip()

    '''
    SCTs fields are represented as multitline fields inside the OCSP response 
    There may be a better way for parsing this, but for the moment this works.
    One can test it by pointing the sample client to e.g. sslanalyzer.comodoca.com
    '''
    def _get_scts_from_text_output(self):
        value = self._ocsp_response.as_text().split('CT Certificate SCTs:')
        scts = [] # list of all Signed Certificate Timestamps found
        current_field = ''
        sct = {} # a single SCT
        if len(value) >1:
            value=value[1].split('Signature Algorithm:')
            for line in value[0].split('\n'):
                line = line.strip()
                if 'Signed Certificate Timestamp:' in line:
                    if sct:
                        scts.append(sct)
                        sct = {}
                        current_field = ''
                else:
                    if 'Version' in line:
                        current_field = ''
                        sct['version']=line[12:]
                    elif 'Log ID' in line:
                        current_field = 'logId'
                        sct[current_field]=line[12:]
                    elif 'Timestamp' in line:
                        current_field = ''
                        sct['timestamp'] = line[12:]
                    elif 'Extensions' in line:
                        current_field = ''
                        sct['extensions'] = line[12:]
                    elif 'Signature' in line:
                        current_field = 'signature'
                        sct[current_field] = line[12:]+u' '
                    elif current_field:
                        sct[current_field] = sct[current_field]+line
                    else:
                        #no known field
                        continue

        else: 
            return None
        scts.append(sct)
        return scts
