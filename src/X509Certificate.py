#!/usr/bin/python


class X509Certificate:
    """
    High level API implementing an X509 certificate.
    """


    def __init__(self, x509):
        self._x509 = x509 
        
    
    def as_text(self):
        return self._x509.as_text()
        
        
    def as_dict(self):
        certDict = \
            {'version': self._x509.get_version() ,
             'serialNumber': self._x509.get_serialNumber() ,
             #'issuer': self._x509.get_issuer_name().get_all_entries() ,
             'validity': {'notBefore': self._x509.get_notBefore() ,
                         'notAfter' : self._x509.get_notAfter()} ,
             #'subject': self._x509.get_subject_name().get_all_entries() ,
             #'subjectPublicKeyInfo':{'publicKeyAlgorithm': self._x509.get_pubkey_algorithm() ,
             #                        'publicKeySize': str( self._x509.get_pubkey_size()*8) ,
             #                        'publicKey': {'modulus': self._x509.get_pubkey_modulus_as_text(),
             #                                      'exponent': self._x509.get_pubkey_exponent_as_text()}
             #                        },
             'extensions': self._parse_x509_extensions() ,
             #'signatureAlgorithm': self._x509.get_signature_algorithm() ,
             #'signatureValue': self._x509.get_signature_as_text() 
             }
        
        return certDict

        
    
    def _parse_x509_extensions(self):
        x509extParsingFunctions = {
            'X509v3 Subject Alternative Name': self._parse_multi_valued_extension,
            'X509v3 CRL Distribution Points': self._parse_crl_distribution_points,
            'Authority Information Access': self._parse_authority_information_access,
            'X509v3 Key Usage': self._parse_multi_valued_extension,
            'X509v3 Extended Key Usage': self._parse_multi_valued_extension,
            'X509v3 Certificate Policies' : self._parse_crl_distribution_points,
            'X509v3 Issuer Alternative Name' : self._parse_crl_distribution_points}
        
        extCount = self._x509.get_ext_count()
        extDict = {}

        for i in xrange(0,extCount):
            x509ext = self._x509.get_ext(i)
            extName = x509ext.get_object()
            extData = x509ext.get_data()
            if extName in x509extParsingFunctions.keys():
                extDict[extName] = x509extParsingFunctions[extName](extData)
            else:
                extDict[extName] = extData
                
        return extDict


# X509 Extension Parsing Functions
    def _parse_multi_valued_extension(self, extension):
        
        extension = extension.split(', ')
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
        
    
    def _parse_authority_information_access(self, auth_ext):
        # Hazardous attempt at parsing an Authority Information Access extension
        auth_ext = auth_ext.strip(' \n').split('\n')
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
            
              
    def _parse_crl_distribution_points(self, crl_ext):
        # Hazardous attempt at parsing a CRL Distribution Point extension
        crl_ext = crl_ext.strip(' \n').split('\n')
        subcrl = {}

        for distrib_point in crl_ext:
            distrib_point = distrib_point.strip()
            distrib_point = distrib_point.split(':', 1)
            if distrib_point[0] != '':
                if subcrl.has_key(distrib_point[0].strip()):
                    subcrl[distrib_point[0].strip()].append(distrib_point[1].strip())
                else:
                    subcrl[distrib_point[0].strip()] = [(distrib_point[1].strip())]

        return subcrl
        
        
        
        