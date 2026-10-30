#!/usr/bin/env bash
set -euo pipefail
mkdir -p racine/{certs,crl,newcerts} inter/{certs,crl,newcerts}
touch racine/index.txt inter/index.txt
echo 1000 > racine/serial; echo 2000 > inter/serial
echo 1000 > racine/crlnumber; echo 2000 > inter/crlnumber

# --- AC racine (cle P-384, 10 ans) ---
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

# --- AC intermediaire (5 ans), contrainte de nom .tp.local ---
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
openssl req -new -key inter/inter.key -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" -out inter/inter.csr
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt
cat inter/inter.crt racine/racine.crt > inter/chaine.crt

# --- Certificat serveur (90 jours) ---
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur.csr -out serveur.crt

# --- Certificat client (pour l'authentification mutuelle) ---
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out alice.key
openssl req -new -key alice.key -subj "/CN=alice@tp.local" -out alice.csr
openssl ca -batch -config inter.cnf -extensions ext_client -days 90 \
  -in alice.csr -out alice.crt
