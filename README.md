# RPKI scripts

Scripts to parse and process RPKI files, e.g. from 

## Requirements

* Python 3
* asn1crypto

```
pip install asn1crypto
```

## Convert to JSON

Convert RPKI related files encoded using ASN.1 (.roa, .mft, .cer, .crl) to readable JSON format (including rewrite of IP prefixes).

```
python3 dump_json.py test.roa
```
