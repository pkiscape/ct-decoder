# ct-decoder
A Python-based Precertificate Signed Certificate Timestamp decoder and lookup tool

This Python script will decode the Precertificate Signed Certificate Timestamps (SCT) of a given x509 certificate. An SCT is a proof that a certificate has been logged in certificate transparency (CT) which means that its issuance was public. More information about this is noted [here](https://github.com/google/certificate-transparency/blob/2588562fd306a447958471b6f06c1069619c1641/docs/SCTValidation.md).

**It is important to download the latest version of known CT loggers that are compliant with Chrome's CT policy:** 
https://www.gstatic.com/ct/log_list/v3/all_logs_list.json
Please ensure that you are using cryptography version 3.1 or greater

**Place the file "all_logs_list.json" in the same directory as ct-decoder.py**

    wget https://www.gstatic.com/ct/log_list/v3/all_logs_list.json

Referenced [here](https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md)

    usage: ctdecoder.py [-h] [-c CERTIFICATE]

    A python-based Precertificate Signed Certificate Timestamp decoder and lookup tool

    optional arguments:
      -h, --help                
                       Show this help message and exit
      -c CERTIFICATE, --certificate CERTIFICATE
                       Define X509 certificate to decode. Can be in PEM or DER.
                      
                      
Examples:
 
    ctdecoder.py -c certificate.pem
or
 
    ctdecoder.py --certificate certificate.pem
                                                               
------
