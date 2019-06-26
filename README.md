# RPKI scripts

Scripts to parse and process RPKI files, e.g. from RIPE NCC's repository.

## Requirements

* Python 3
* asn1crypto

```
pip install -r requirements.txt
```

## Download RPKI data

RPKI data can be downloaded from AFRINIC, APNIC, LACNIC and RIPE NCC using the following script:
```
sh download_rpki.sh
```
The scripts requires rsync to be installed. The data will be downloaded into the directory `data`.

For the data from ARIN, visit https://www.arin.net/resources/rpki/tal.html for their Relying Party Agreement.

## Convert to JSON

Convert RPKI related files encoded using ASN.1 (.roa, .mft, .cer, .crl) to readable JSON format (including rewrite of IP prefixes).

```
python3 dump_json.py test.roa
```
