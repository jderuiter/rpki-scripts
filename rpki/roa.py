from asn1crypto.cms import ContentType, EncapsulatedContentInfo
from asn1crypto.core import BitString, Integer, OctetString, Sequence, \
    SequenceOf

# RFC 6482 - A Profile for Route Origin Authorizations (ROAs)
# https://tools.ietf.org/html/rfc6482


class IPAddress(BitString):
    pass


class ROAIPAddress(Sequence):
    _fields = [
        ('address', IPAddress),
        ('maxLength', Integer, {'optional': True})
    ]


class ROAIPAddressSet(SequenceOf):
    _child_spec = ROAIPAddress


class ROAIPAddressFamily(Sequence):
    _fields = [
        ('addressFamily', OctetString),
        ('addresses', ROAIPAddressSet),
    ]


class ROAIPAddressFamilySeq(SequenceOf):
    _child_spec = ROAIPAddressFamily


class ASID(Integer):
    pass


class RouteOriginAttestation(Sequence):
    _fields = [
        ('version', Integer, {'implicit': 0, 'default': 0}),
        ('asID', ASID),
        ('ipAddrBlocks', ROAIPAddressFamilySeq),
    ]


# Register OID for routeOriginAuthz
ContentType._map['1.2.840.113549.1.9.16.1.24'] = 'routeOriginAuthz'
EncapsulatedContentInfo._oid_specs['routeOriginAuthz'] = RouteOriginAttestation
