#!/usr/bin/python


class OcspResponse:
    """
    High level API for parsing an OCSP response.
    """


    def __init__(self, ocspResp):
        self._ocspResp = ocspResp
        self._respDict = None


    def as_text(self):
        return self._ocspResp.as_text()


    def verify(self, verifyLocations):
        return self._ocspResp.basic_verify(verifyLocations)


    def as_dict(self):
        if self._respDict:
            return self._respDict

        # For now we just parse OpenSSL's text output and make a lot of assumptions
        respDict = {
            'responseStatus': self._get_value_from_text_output_no_p('OCSP Response Status:'),
            'version' : self._get_value_from_text_output_no_p('Version:'),
            'responseType': self._get_value_from_text_output('Response Type:'),
            'responderID': self._get_value_from_text_output('Responder Id:'),
            'producedAt': self._get_value_from_text_output('Produced At:')}

        if 'successful' not in respDict['responseStatus']:
            return respDict

        respDict['responses'] = [ {
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
        self._respDict = respDict
        return respDict


# Text parsing
    def _get_value_from_text_output(self, key):
        value = self._ocspResp.as_text().split(key)
        return value[1].split('\n')[0].strip()


    def _get_value_from_text_output_no_p(self, key):
        value = self._ocspResp.as_text().split(key)
        value = value[1].split('\n')[0].strip()
        return value.split('(')[0].strip()


