from asn1crypto.algos import DigestAlgorithmId
from asn1crypto.cms import ContentType, EncapsulatedContentInfo
from asn1crypto.core import BitString, GeneralizedTime, IA5String, Integer, \
    Sequence, SequenceOf

# RFC 6486 - Manifests for the Resource Public Key Infrastructure (RPKI)
# https://tools.ietf.org/html/rfc6486


class FileAndHash(Sequence):
    _fields = [
        ('file', IA5String),
        ('hash', BitString),
    ]


class FileAndHashSeq(SequenceOf):
    _child_spec = FileAndHash


class RPKIManifest(Sequence):
    _fields = [
        ('version', Integer, {'implicit': 0, 'default': 0}),
        ('manifestNumber', Integer),
        ('thisUpdate', GeneralizedTime),
        ('nextUpdate', GeneralizedTime),
        ('fileHashAlg', DigestAlgorithmId),
        ('fileList', FileAndHashSeq),
    ]


# Register OID for rpkiManifest
ContentType._map['1.2.840.113549.1.9.16.1.26'] = 'rpkiManifest'
EncapsulatedContentInfo._oid_specs['rpkiManifest'] = RPKIManifest
