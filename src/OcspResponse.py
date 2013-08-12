#!/usr/bin/python
from nassl._nassl import OCSP_RESPONSE

class OcspResponse:
    """
    High level API for parsing an OCSP response.
    """


    def __init__(self, ocspResp):
        self._ocspResp = ocspResp 
        
    
    def as_text(self):
        return self._ocspResp.as_text()
        
        
    def verify(self, verifyLocations):
        return self._ocspResp.basic_verify(verifyLocations)
