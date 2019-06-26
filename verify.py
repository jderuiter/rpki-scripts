from asn1crypto.cms import ContentInfo, CMSAttribute
from asn1crypto.crl import CertificateList
from asn1crypto.core import SetOf

from oscrypto import asymmetric

# Import to register OIDs
import rpki.roa
import rpki.manifest

from rpki.certificate import RPKICertificate

import os
import sys

import hashlib


def main():
    if len(sys.argv) < 2:
        sys.exit("Not enough arguments")

    path = sys.argv[1]

    # TODO Add flag to override detection based on filetype

    # Try to determine type based on extension
    file, ext = os.path.splitext(path)
    ext = ext.lower()

    if ext == '.roa':
        ext_class = ContentInfo
    elif ext == '.mft':
        ext_class = ContentInfo
    elif ext == '.crl':
        ext_class = CertificateList
    elif ext == '.cer':
        ext_class = RPKICertificate
    else:
        sys.exit("Unknown filetype: " + ext)

    # Read file
    try:
        file = open(path, "rb")
        der_byte_string = file.read()
    except Exception as e:
        sys.exit("Could not read file.\n" + str(e))

    # Parse ASN.1 data using previously picked type
    try:
        parsed = ext_class.load(der_byte_string)
    except Exception as e:
        sys.exit("Could not parse file.\n" + str(e))

    # TODO Sanity check of resulting data

    try:
        # Convert to readable JSON output
        data = parsed.native

        if not type(parsed) is ContentInfo:
            raise Exception("Invalid content type (not ROA or RPKI manifest)")

        # Verification according to RFC 5652 - Cryptographic Message Syntax (CMS)

        # Compute message digest
        hash_data = bytes(parsed['content']['encap_content_info']['content'])
        h = hashlib.sha256()
        h.update(hash_data)
        computed_digest = h.digest()

        # Get digest and content type from message
        message_digest = None
        message_content_type = None
        for attr in data['content']['signer_infos'][0]['signed_attrs']:
            if attr['type'] == 'message_digest':
                message_digest = attr['values'][0]
            elif attr['type'] == 'content_type':
                message_content_type = attr['values'][0]

        # Compare message content types
        if data['content']['encap_content_info']['content_type'] == message_content_type:
            print('Content types equal (' + message_content_type + ')')
        else:
            print('Content types not equal')

        # Compare computed digest with digest from message
        if computed_digest == message_digest:
            print('Digests equal')
        else:
            print('Digests not equal')

        # Get certificate and algorithm to be used for verification
        cert = asymmetric.load_certificate(parsed['content']['certificates'][0].chosen)
        hash_algo = 'sha256'

        # Rewrite signed attributes to EXPLICIT SET OF
        signed_data = SetOf(spec=CMSAttribute)
        for child in parsed['content']['signer_infos'][0]['signed_attrs'].children:
            signed_data.append(child)

        # Verify signature
        result = asymmetric.rsa_pkcs1v15_verify(cert, data['content']['signer_infos'][0]['signature'], signed_data.dump(), hash_algo)
        if result is None:
            print("Signature is valid")

        # TODO Verify included certificate is part of a valid chain

    except Exception as e:
        sys.exit("Something went wrong:\n" + str(e))


if __name__ == "__main__":
    main()
