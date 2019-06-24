from asn1crypto.core import BitString, Choice, Integer, Null, OctetString, \
    Sequence, SequenceOf
from asn1crypto.x509 import AccessMethod, Certificate, Extension, \
    ExtensionId, PolicyIdentifier

# RFC 3779 - X.509 Extensions for IP Addresses and AS Identifiers
# https://tools.ietf.org/html/rfc3779


class IPAddress(BitString):
    pass


class IPAddressRange(Sequence):
    _fields = [
        ('min', IPAddress),
        ('max', IPAddress),
    ]


class IPAddressOrRange(Choice):
    _alternatives = [
        ('addressPrefix', IPAddress),
        ('addressRange', IPAddressRange),
    ]


class IPAddressOrRangeSeq(SequenceOf):
    _child_spec = IPAddressOrRange


class IPAddressChoice(Choice):
    _alternatives = [
        ('inherit', Null),
        ('addressesOrRanges', IPAddressOrRangeSeq),
    ]


class IPAddressFamily(Sequence):
    _fields = [
        ('addressFamily', OctetString),
        ('ipAddressChoice', IPAddressChoice),
    ]


class IPAddrBlocks(SequenceOf):
    _child_spec = IPAddressFamily


class ASId(Integer):
    pass


class ASRange(Sequence):
    _fields = [
        ('min', ASId),
        ('max', ASId),
    ]


class ASIdOrRange(Choice):
    _alternatives = [
        ('id', ASId),
        ('range', ASRange),
    ]


class ASIdOrRangeSeq(SequenceOf):
    _child_spec = ASIdOrRange


class ASIdentifierChoice(Choice):
    _alternatives = [
        ('inherit', Null),
        ('asIdsOrRanges', ASIdOrRangeSeq),
    ]


class ASIdentifiers(Sequence):
    _fields = [
        ('asnum', ASIdentifierChoice, {'explicit': 0, 'optional': True}),
        ('rdi', ASIdentifierChoice, {'explicit': 1, 'optional': True}),
    ]


class RPKICertificate(Certificate):
    pass


ExtensionId._map['1.3.6.1.5.5.7.1.7'] = 'id-pe-ipAddrBlocks'
ExtensionId._map['1.3.6.1.5.5.7.1.8'] = 'id-pe-autonomousSysIds'

Extension._oid_specs['id-pe-ipAddrBlocks'] = IPAddrBlocks
Extension._oid_specs['id-pe-autonomousSysIds'] = ASIdentifiers

PolicyIdentifier._map['1.3.6.1.5.5.7.14.2'] = 'id-cp-ipAddr-asNumber'

AccessMethod._map['1.3.6.1.5.5.7.48.10'] = 'id-ad-rpkiManifest'
AccessMethod._map['1.3.6.1.5.5.7.48.13'] = 'id-ad-rpkiNotify'
