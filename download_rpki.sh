#!/bin/sh

echo "Download RPKI data from RIPE NCC"
mkdir -p data/ripe-ncc
rsync -r rsync://rpki.ripe.net/repository/ data/ripe-ncc

echo "Download RPKI data from AFRINIC"
mkdir -p data/afrinic
rsync -r rsync://rpki.afrinic.net/repository/ data/afrinic

echo "Download RPKI data from APNIC"
mkdir -p data/apnic
rsync -r rsync://rpki.apnic.net/member_repository/ data/apnic

echo "Download RPKI data from LACNIC"
mkdir -p data/lacnic
rsync -r rsync://repository.lacnic.net/rpki/ data/lacnic
