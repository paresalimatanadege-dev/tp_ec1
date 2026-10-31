#!/usr/bin/env bash
# Renouvelle le certificat de www.tp.local s'il expire bientôt.
# À lancer en root : il écrit dans /etc/nginx/tls et recharge nginx.
set -euo pipefail
umask 077

[ "$(id -u)" -eq 0 ] || { echo "Erreur : à lancer avec sudo." >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI="${PKI:-$SCRIPT_DIR/../tp2/pki}"
TLS="${TLS:-/etc/nginx/tls}"
SEUIL_JOURS="${SEUIL_JOURS:-30}"
NOM="www.tp.local"

cd "$PKI"

# 0. Faut-il renouveler ?
if openssl x509 -in "$TLS/serveur_chaine.crt" -noout \
     -checkend $((SEUIL_JOURS * 86400)) > /dev/null; then
  echo "Certificat valable plus de $SEUIL_JOURS jours : rien à faire."
  exit 0
fi
echo "Le certificat expire dans moins de $SEUIL_JOURS jours : renouvellement."

TRAVAIL="$(mktemp -d)"
trap 'rm -rf "$TRAVAIL"' EXIT

# 1. Nouvelle clé et nouvelle demande
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$TRAVAIL/serveur.key"
openssl req -new -key "$TRAVAIL/serveur.key" -subj "/CN=$NOM" \
  -addext "subjectAltName=DNS:$NOM,DNS:tp.local" -out "$TRAVAIL/serveur.csr"

# 2. Signature par l'intermédiaire
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in "$TRAVAIL/serveur.csr" -out "$TRAVAIL/serveur.crt"

# 3. Contrôles AVANT tout déploiement
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname "$NOM" "$TRAVAIL/serveur.crt"
[ "$(openssl x509 -in "$TRAVAIL/serveur.crt" -noout -pubkey)" = \
  "$(openssl pkey -in "$TRAVAIL/serveur.key" -pubout)" ] \
  || { echo "Erreur : le certificat ne correspond pas à la clé." >&2; exit 1; }
cat "$TRAVAIL/serveur.crt" inter/inter.crt > "$TRAVAIL/serveur_chaine.crt"

# 4. Sauvegarde de l'ancien certificat et de l'ancienne clé
ANCIEN="$TLS/anciens/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$ANCIEN"
cp -p "$TLS/serveur.key" "$TLS/serveur_chaine.crt" "$ANCIEN/"

# 5. Déploiement, test de la configuration, rechargement
install -m 600 "$TRAVAIL/serveur.key" "$TLS/serveur.key"
install -m 644 "$TRAVAIL/serveur_chaine.crt" "$TLS/serveur_chaine.crt"
if ! nginx -t; then
  echo "Configuration invalide : retour arrière." >&2
  install -m 600 "$ANCIEN/serveur.key" "$TLS/serveur.key"
  install -m 644 "$ANCIEN/serveur_chaine.crt" "$TLS/serveur_chaine.crt"
  exit 1
fi
systemctl reload nginx

# 6. Garder le dossier de la PKI cohérent avec ce qui est déployé
cp "$TRAVAIL/serveur.key" serveur.key
cp "$TRAVAIL/serveur.crt" serveur.crt
cp "$TRAVAIL/serveur_chaine.crt" serveur_chaine.crt
chown -R --reference="$PKI" "$PKI"
echo "Renouvellement terminé : nouveau certificat en service."
