#!/bin/bash

# /etc/ssh/sshd_config:
#
# PubkeyAuthentication yes
# AuthorizedKeysFile    /etc/ssh/authorized_keys/%u
# AuthorizedKeysCommand /path/to/this/script
# or
# AuthorizedKeysCommand /path/to/this/script site_name


# Exit on any non-zero exit code
set -o errexit

# Exit on any unset variable
set -o nounset

# Pipeline's return status is the value of the last (rightmost) command 
# to exit with a non-zero status, or zero if all commands exit successfully.
set -o pipefail

# Set restrictive umask
umask 0177

# Start with an empty environment
/bin/env -i

. /usr/libexec/pivauth/functions.sh

# Paths to external tools
OPENSSL="/usr/bin/openssl"
LDAPSEARCH="/usr/bin/ldapsearch"
CAT="/bin/cat"
RM="/bin/rm"
GREP="/bin/grep"
SED="/bin/sed"
MKTEMP="/bin/mktemp"
PUBKEY2SSH="/usr/bin/pubkey2ssh"

# If there are two arguments the first will be a site specification
# which will be used in defining the config file path
if [ $# -eq 2 ]; then
  if [ -z "${1:-}" ]; then
    error "Site argument empty"
  else
    SITE="${1}"
  fi
  shift
fi

# First argument is user name
if [ -z "${1:-}" ]; then
  error "No user supplied"
else 
  SSHUSER="${1}"
  # Dump all the args so they can't be accessed later
  shift $#
fi


# Ensure the user name input is valid
validate_username "${SSHUSER}" || error "Invalid user supplied"

# Import the config after SSHUSER is defined so we can make use of it
# If SITE is defined prepend it to the config file name
if [ ! -z "${SITE:-}" ]; then
  . /etc/sysconfig/pivauth."${SITE}"
else
  . /etc/sysconfig/pivauth
fi

# Check if user is in lookup table
if [ ! -z "${LDAP_USER_LOOKUP_TABLE["${SSHUSER}"]:-}" ]; then
  SSHUSER="${LDAP_USER_LOOKUP_TABLE["${SSHUSER}"]}"
fi

# Mark the SSHUSER variable as readonly so nothing else can modify it
readonly SSHUSER

# Reread config after LDAP_USER_LOOKUP_TABLE is checked to update any use of SSHUSER
# Import the config after SSHUSER is defined so we can make use of it
# If SITE is defined prepend it to the config file name
if [ ! -z "${SITE:-}" ]; then
  . /etc/sysconfig/pivauth."${SITE}"
else
  . /etc/sysconfig/pivauth
fi

check_options

# Validate checksum of CA certificates
validate_ca_checksum "${CACERTS_SHA512}" || error "CA Checksum failed"

# Create temp file for CA Bundle
CABUNDLE=$("${MKTEMP}")

# Ensure CA Bundle is empty
>"${CABUNDLE}"

# Concatinate CA Certs into Bundle
for CACERT in ${CACERTS}; do
  "${CAT}" "${CACERT}" >> "${CABUNDLE}"
done

# Check if the user cert signing CA certificate has been revoked by the intermediate CA
check_cert_revocation "${INTERMEDIATE_CA}" "${USER_CERT_ISSUER}" "${OCSP_RESPONDER}" "${CABUNDLE}" "${OCSP_ENABLE}" "${INTERMEDIATE_CRL_URL}" "${VALIDITY_PERIOD}" \
  || error "Revocation check of Intermediate CA failed"

# Fetch user certificates from LDAP
SEARCH=$({ "${LDAPSEARCH}" -ZZx -t -H "${LDAP_URI}" -D "${LDAP_BINDDN}" -y "${LDAP_BIND_PASS}" -b "${LDAP_BASE_DN}" "${LDAP_USER_SEARCH}" "${LDAP_CERT_ATTR}" | "${GREP}" "${LDAP_CERT_ATTR}:<" | "${SED}" -e "s/${LDAP_CERT_ATTR}:< file:\/\///"; } || error "No x509 certifcates found in LDAP for ${SSHUSER}")

# Validate certificate against CA chain, OCSP, and CRL
VALID_CERTS=()
for CERT in $SEARCH; do 
  CERT_PEM="${CERT}.pem"

  # Convert from DER to PEM
  "${OPENSSL}" x509 -inform DER -outform PEM -in "${CERT}" -out "${CERT_PEM}"
  # Cleanup DER formated cert
  "${RM}" -f "${CERT}" || true

  CERT_FINGERPRINT=$("${OPENSSL}" x509 -noout -fingerprint -in "${CERT_PEM}")

  # Check if certificate is revoked
  check_cert_revocation "${USER_CERT_ISSUER}" "${CERT_PEM}" "${OCSP_RESPONDER}" "${CABUNDLE}" "${OCSP_ENABLE}" "${CRL_URL}" "${VALIDITY_PERIOD}" || { warn "Certificate ${CERT_FINGERPRINT} failed revocation check for user ${SSHUSER}"; "${RM}" -f "${CERT_PEM}" || true; continue; }

  # Check CA Chain
  validate_cert_ca "${CERT_PEM}" "${CABUNDLE}" || { warn "Certificate ${CERT_FINGERPRINT} failed CA trust check for user ${SSHUSER}"; "${RM}" -f "${CERT_PEM}" || true; continue; }

  VALID_CERTS+=("${CERT_PEM}")

  info "Found valid x509 certificate ${CERT_FINGERPRINT} for ${SSHUSER}"

done

# Cleanup temp CABundle
"${RM}" -f "${CABUNDLE}" || true

if [ ${#VALID_CERTS[@]} -eq 0 ]; then
  error "No valid x509 certifcates found for ${SSHUSER}"
fi

# Extract the RSA pubkey from the x509 cert, and convert into expected
# format for OpenSSH. Print SSH pubkey to stdout.
for VALID_CERT in "${VALID_CERTS[@]}"; do
  PUBKEY=${VALID_CERT%.pem}.pub
  "${OPENSSL}" x509 -in "${VALID_CERT}" -noout -pubkey > "${PUBKEY}"
  "${RM}" -f "${VALID_CERT}" || true
  
  # Using https://www.idrix.fr/Root/Samples/pubkey2ssh.c below as ssh-keygen
  # on RHEL6 only supports import from RFC 4716 SSH Public Key File Format
  "${PUBKEY2SSH}" "${PUBKEY}" "${SSH_PUBKEY_COMMENT}"
  
  #  Cleanup pubkey
  "${RM}" -f "${PUBKEY}" || true
done
