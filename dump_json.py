from asn1crypto.cms import ContentInfo
from asn1crypto.crl import CertificateList

import rpki.roa
import rpki.manifest
from rpki.certificate import RPKICertificate

import os
import sys

import socket
import json
from datetime import datetime

ADDRESS_FAMILY_IPV4 = b'\x00\x01'
ADDRESS_FAMILY_IPV6 = b'\x00\x02'


# Turn a tuple of bits into a byte string. The number of bits needs to be a
# multiple of 8.
def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise ValueError("Number of bits not a multiple of 8")

    out = []
    for i in range(0, len(bits) >> 3):
        v = 0
        for j in range(0, 8):
            v |= bits[i*8+j] << j
        out.append(v)
    return bytes(out)


# Print bits as IPv4 prefix in CIDR notation
def ipv4_prefix_to_string(bits):
    if len(bits) > 32:
        raise ValueError("Too many bits for IPv4 prefix")

    # Extend bits to full IPv4 length
    prefix = bits + tuple(0 for _ in range(32 - len(bits)))

    b = bits_to_bytes(prefix)
    str_prefix = socket.inet_ntop(socket.AF_INET, b) + "/" + str(len(bits))
    return str_prefix


# Print bits as IPv6 prefix in CIDR notation
def ipv6_prefix_to_string(bits):
    if len(bits) > 128:
        raise ValueError("Too many bits for IPv6 prefix")

    # Extend bits to full IPv6 length
    prefix = bits + tuple(0 for _ in range(128 - len(bits)))

    b = bits_to_bytes(prefix)
    str_prefix = socket.inet_ntop(socket.AF_INET6, b) + "/" + str(len(bits))
    return str_prefix


# Rewrite ipAddrBlocks in native format to readable prefixes
def rewrite_ipAddrBlocks(ipAddrBlocks):
    for ipAddrBlock in ipAddrBlocks:
        if ipAddrBlock['addressFamily'] == ADDRESS_FAMILY_IPV4:
            ipAddrBlock['addressFamily'] = 'IPv4'
            for k in range(0, len(ipAddrBlock['addresses'])):
                # Rewrite IP prefix from bits to readable string
                ipAddrBlock['addresses'][k]['address'] = ipv4_prefix_to_string(ipAddrBlock['addresses'][k]['address'])
                # TODO Check max_length is consistent with prefix length?
        elif ipAddrBlock['addressFamily'] == ADDRESS_FAMILY_IPV6:
            ipAddrBlock['addressFamily'] = 'IPv6'
            for k in range(0, len(ipAddrBlock['addresses'])):
                # Rewrite IP prefix from bits to readable string
                ipAddrBlock['addresses'][k]['address'] = ipv6_prefix_to_string(ipAddrBlock['addresses'][k]['address'])
                # TODO Check max_length is consistent with prefix length?
        else:
            raise ValueError("Invalid addressFamily")


# Return version of object that can be converted to JSON.
# Byte strings are converted to hex, datetime to isoformat, sets to lists.
def jsonize_object(obj):
    if isinstance(obj, dict):
        return dict(map(lambda i: (i[0], jsonize_object(i[1])), obj.items()))
    elif isinstance(obj, list) or isinstance(obj, set):
        return list(map(jsonize_object, obj))
    elif type(obj) == bytes:
        return obj.hex()
    elif type(obj) == datetime:
        return obj.isoformat()
    else:
        return obj


def process_roa(roa):
    # Rewrite the IP addresses in the ipAddrBlocks to readable prefixes
    rewrite_ipAddrBlocks(roa['ipAddrBlocks'])


def process_manifest(manifest):
    # Rewrite hashes to hex/bytes
    for fileHash in manifest['fileList']:
        fileHash['hash'] = bits_to_bytes(fileHash['hash']).hex()


def process_certificate(certificate):
    # Rewrite ipAddressChoice
    for ext in certificate['tbs_certificate']['extensions']:
        if ext['extn_id'] == 'id-pe-ipAddrBlocks':
            for ipAddrFamily in ext['extn_value']:
                if ipAddrFamily['addressFamily'] == ADDRESS_FAMILY_IPV4:
                    ipAddrFamily['addressFamily'] = 'IPv4'
                    if ipAddrFamily['ipAddressChoice']:
                        for k in range(0, len(ipAddrFamily['ipAddressChoice'])):
                            # Rewrite IP prefix from bits to readable string
                            ipAddrFamily['ipAddressChoice'][k] = ipv4_prefix_to_string(ipAddrFamily['ipAddressChoice'][k])
                elif ipAddrFamily['addressFamily'] == ADDRESS_FAMILY_IPV6:
                    ipAddrFamily['addressFamily'] = 'IPv6'
                    if ipAddrFamily['ipAddressChoice']:
                        for k in range(0, len(ipAddrFamily['ipAddressChoice'])):
                            # Rewrite IP prefix from bits to readable string
                            ipAddrFamily['ipAddressChoice'][k] = ipv6_prefix_to_string(ipAddrFamily['ipAddressChoice'][k])


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

        if type(parsed) is ContentInfo:
            for cert in data['content']['certificates']:
                process_certificate(cert)

            if data['content']['encap_content_info']['content_type'] == 'routeOriginAuthz':
                process_roa(data['content']['encap_content_info']['content'])
            elif data['content']['encap_content_info']['content_type'] == 'rpkiManifest':
                process_manifest(data['content']['encap_content_info']['content'])
        elif type(parsed) is RPKICertificate:
            process_certificate(data)
        elif type(parsed) is CertificateList:
            pass
        else:
            sys.exit("Unkown content type")

        print(json.dumps(jsonize_object(data), indent=2))
    except Exception as e:
        sys.exit("Something went wrong:\n" + str(e))


if __name__ == "__main__":
    main()
