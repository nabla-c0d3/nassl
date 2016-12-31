#!/usr/bin/python2.7


class OcspResponse:
    """High level API for parsing an OCSP response.
    """


    def __init__(self, ocsp_response):
        # type: (nassl._nassl.OCSP_RESPONSE) -> None
        self._ocsp_response = ocsp_response
        self._ocsp_response_dict = None


    def as_text(self):
        # type: () -> str
        return self._ocsp_response.as_text()


    def verify(self, verify_locations):
        # type: (str) -> None
        return self._ocsp_response.basic_verify(verify_locations)


    def as_dict(self):
        # type: () -> Dict[str, str]
        if self._ocsp_response_dict:
            return self._ocsp_response_dict

        # For now we just parse OpenSSL's text output and make a lot of assumptions
        response_dict = {
            'responseStatus': self._get_value_from_text_output_no_p('OCSP Response Status:'),
            'version' : self._get_value_from_text_output_no_p('Version:'),
            'responseType': self._get_value_from_text_output('Response Type:'),
            'responderID': self._get_value_from_text_output('Responder Id:'),
            'producedAt': self._get_value_from_text_output('Produced At:')}

        if 'successful' not in response_dict['responseStatus']:
            return response_dict

        response_dict['responses'] = [ {
                                      'certID': {
                'hashAlgorithm': self._get_value_from_text_output('Hash Algorithm:'),
                'issuerNameHash': self._get_value_from_text_output('Issuer Name Hash:'),
                'issuerKeyHash': self._get_value_from_text_output('Issuer Key Hash:'),
                'serialNumber': self._get_value_from_text_output('Serial Number:')
                },
            'certStatus': self._get_value_from_text_output('Cert Status:'),
            'thisUpdate': self._get_value_from_text_output('This Update:'),
            'nextUpdate': self._get_value_from_text_output('Next Update:')
            }]
        self._ocsp_response_dict = response_dict
        return response_dict


# Text parsing
    def _get_value_from_text_output(self, key):
        # type: (str) -> str
        value = self._ocsp_response.as_text().split(key)
        return value[1].split('\n')[0].strip()


    def _get_value_from_text_output_no_p(self, key):
        # type: (str) -> str
        value = self._ocsp_response.as_text().split(key)
        value = value[1].split('\n')[0].strip()
        return value.split('(')[0].strip()


