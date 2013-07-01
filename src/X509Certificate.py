#!/usr/bin/python


class X509Certificate:
    """
    High level API for parsing an X509 certificate.
    """


    def __init__(self, x509):
        self._x509 = x509 
        
    
    def as_text(self):
        return self._x509.as_text()
        
    
    def as_pem(self):
        return self._x509.as_pem()


    def get_SHA1_fingerprint(self):
        return self._x509.digest()
        
        
    def as_dict(self):
        certDict = \
            {'version': self._x509.get_version() ,
             'serialNumber': self._x509.get_serialNumber() ,
             'issuer': self._parse_x509_name(self._x509.get_issuer_name_entries()) ,
             'validity': {'notBefore': self._x509.get_notBefore() ,
                         'notAfter' : self._x509.get_notAfter()} ,
             'subject': self._parse_x509_name(self._x509.get_issuer_name_entries()) ,
             'subjectPublicKeyInfo': self._parse_pubkey(),
             'extensions': self._parse_x509_extensions() ,
             'signatureAlgorithm': self._parse_signature_algorithm() ,
             'signatureValue': self._parse_signature() 
             }
        
        return certDict
    
    
# "Private" methods

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
    

    def _parse_x509_name(self, nameEntries):
        nameEntriesDict= {}
        for entry in nameEntries:
            nameEntriesDict[entry.get_object()] = entry.get_data()
        return nameEntriesDict


# Public Key Parsing Functions
# The easiest and ugliest way to do this is to just parse OpenSSL's text output
# I don't want to create an EVP_PKEY class in C just for this
        
    def _parse_pubkey(self):
                
        pubkeyDict = {
            'publicKeyAlgorithm': self._parse_pubkey_algorithm() ,
            'publicKeySize': str( self._parse_pubkey_size()) ,
            'publicKey': {'modulus': self._parse_pubkey_modulus(),
                          'exponent': self._parse_pubkey_exponent() } 
                      }
        return pubkeyDict


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
        x509extParsingFunctions = {
            'X509v3 Subject Alternative Name': self._parse_multi_valued_extension,
            'X509v3 CRL Distribution Points': self._parse_crl_distribution_points,
            'Authority Information Access': self._parse_authority_information_access,
            'X509v3 Key Usage': self._parse_multi_valued_extension,
            'X509v3 Extended Key Usage': self._parse_multi_valued_extension,
            'X509v3 Certificate Policies' : self._parse_crl_distribution_points,
            'X509v3 Issuer Alternative Name' : self._parse_crl_distribution_points }

        extDict = {}

        for x509ext in self._x509.get_extensions():
            extName = x509ext.get_object()
            extData = x509ext.get_data()
            # TODO: Should we output the critical field ?
            extCrit = x509ext.get_critical()
            if extName in x509extParsingFunctions.keys():
                extDict[extName] = x509extParsingFunctions[extName](extData)
            else:
                extDict[extName] = extData.strip()
                
        return extDict


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
        
        
        
        