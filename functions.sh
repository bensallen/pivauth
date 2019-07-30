#!/bin/bash

## Function return codes
# 0 - success
# 1 - failure
# 2 - input validation failure
# 3 - misc failure

# Paths to external tools
OPENSSL="/usr/bin/openssl"
GREP="/bin/grep"
SHA512SUM="/usr/bin/sha512sum"
GETENT="/usr/bin/getent"
LOGGER="/bin/logger"
CURL="/usr/bin/curl"
CAT="/bin/cat"
RM="/bin/rm"
BASENAME="/bin/basename"
DIRNAME="/usr/bin/dirname"
MKDIR="/bin/mkdir"

# Logging
LOGGER_ERR_FACILITY="authpriv.err"
LOGGER_ERR_TAG="pivauth"
LOGGER_WARN_FACILITY="authpriv.warn"
LOGGER_WARN_TAG="pivauth"
LOGGER_INFO_FACILITY="authpriv.info"
LOGGER_INFO_TAG="pivauth"

# Exit on any unset variable
set -o nounset

# Pipeline's return status is the value of the last (rightmost) command 
# to exit with a non-zero status, or zero if all commands exit successfully.
set -o pipefail

# Set restrictive umask
umask 0077

# Start with an empty environment
env -i

# Validate the input username is sane
validate_username() {
  local user=$1

  if [ -z "${user:-}" ]; then
    return 2
  fi

  # Ensure the user name input contains valid charecters
  "${GREP}" -q -E '^[-_[:alnum:]]+$' <<< "${user}" || return 1
  # Check that the user name is valid on the system
  "${GETENT}" passwd "${user}" >/dev/null || return 1
  return 0
}

# Validate checksum of CA certificates
validate_ca_checksum() {
  local cacerts_sha512=$1
  local chksum

  if [ -z "${cacerts_sha512:-}" ]; then
    return 2
  fi

  for chksum in "${cacerts_sha512}"; do
    echo "$chksum" | "${SHA512SUM}" -c --quiet >/dev/null 2>&1 || return 1
  done

  return 0
}

# Check revocation status
validate_cert_ocsp() {
  local issuer=$1
  local cert=$2
  local url=$3
  local ca_bundle=$4
  local validity_period=$5
  local result


  if [ -z "${issuer:-}" ] || [ -z "${cert:-}" ] || [ -z "${url:-}" ] || [ -z "${ca_bundle:-}" ] || [ -z "${validity_period:-}" ]; then
    return 2
  fi

  result=$("${OPENSSL}" ocsp -validity_period "${validity_period}" -issuer "${issuer}" -cert "${cert}" -url "${url}" -CAfile "${ca_bundle}" 2>/dev/null) || return 3
  
  echo "${result}" | "${GREP}" -q "^${cert}: good$" && return 0 || return 1

}

# Check CA Chain
validate_cert_ca() {
  local cert=$1
  local ca_bundle=$2

  if [ -z "${cert:-}" ] || [ -z "${ca_bundle:-}" ]; then
    return 2
  fi

  "${OPENSSL}" verify -x509_strict -CAfile "${ca_bundle}" "${cert}" 2>/dev/null | "${GREP}" -q "^${cert}: OK$" && return 0 || return 1

}

# Fetch CRL
fetch_crl() {
  local crl_path=$1
  local crl_url=$2

  if [ -z "${crl_path:-}" ] || [ -z "${crl_url:-}" ]; then
    return 2
  fi

  # Check that we have a fully qualified path
  if [ "${crl_path:0:1}" != '/' ]; then
    return 2
  fi

  local crl_dir=$("${DIRNAME}" "${crl_path}")

  "${MKDIR}" -p "${crl_dir}" || return 2

  "${CURL}" --silent --time-cond "${crl_path}" --output "${crl_path}" --remote-name "${crl_url}" --compress && return 0 || return 1

}

# Validate Cert against CRL
validate_cert_crl() {
  local crl_path="${1}"
  local ca_bundle="${2}"
  local cert="${3}"
  local crl_format="${4:-DER}"
  local RC

  if [ -z "${crl_path:-}" ] || [ -z "${ca_bundle:-}" ] || [ -z "${cert:-}" ]; then
    return 2
  fi


  if [ ! -e "${crl_path:-}" ] || [ ! -e "${ca_bundle:-}" ] || [ ! -e "${cert:-}" ]; then
    return 2
  fi

  local temp_ca_bundle
  temp_ca_bundle=$(mktemp) || return 3

  "${OPENSSL}" crl -inform "${crl_format}" -in "${crl_path}" -outform PEM -out "${temp_ca_bundle}" 2>/dev/null || return 3

  "${CAT}" "${ca_bundle}" >> "${temp_ca_bundle}" || return 3

  "${OPENSSL}" verify -x509_strict -crl_check -CAfile "${temp_ca_bundle}" "${cert}" 2>/dev/null | "${GREP}" -q "^${cert}: OK$" && RC=0 || RC=1

  "${RM}" -f "${temp_ca_bundle}" || true

  return "${RC}"

}

# Check if certificate if revoked via OCSP, falling though to fetching
# CRL and checking against the CRL
check_cert_revocation() {
  local issuer=$1
  local cert=$2
  local ocsp_url=$3
  local ca_bundle=$4
  local ocsp_enable=$5
  local crl_url=$6
  local validity_period=$7

  local crl_path
  local RC=254

  if [ -z "${issuer:-}" ] || [ -z "${cert:-}" ] || [ -z "${ocsp_url:-}" ] || [ -z "${ca_bundle:-}" ] || [ -z "${ocsp_enable:-}" ] || [ -z "${crl_url:-}" ] || [ -z "${validity_period:-}" ]; then
    return 2
  fi

  if [ "${ocsp_enable}" -eq 1 ]; then
    { validate_cert_ocsp "${issuer}" "${cert}" "${ocsp_url}" "${ca_bundle}" "${validity_period}"; RC=$?; }
    
    # If cert was not verified (RC=0) and failed for another reason than not being able to contact OCSP (RC=3)
    if [ "${RC}" -ne 0 ] && [ "${RC}" -ne 3 ]; then
      return 1
    else
      return 0
    fi
  fi

  # If OCSP is disabled or OCSP failed due to not being able to connect to the responder
  # fall through to fetch the CRL and check revocation via the CRL
  if [ "${ocsp_enable}" -ne 1 ] || [ "${RC}" -eq 3 ]; then
  
    crl_path="${CACHE_DIR}"/"$("${BASENAME}" "${crl_url}")" || return 2
    fetch_crl "${crl_path}" "${crl_url}" || return 1
    validate_cert_crl "${crl_path}" "${ca_bundle}" "${cert}" || return 1

    return 0
  fi

}

# Basic validation of configuration options
check_options() {
  local options=("${LDAP_URI}" "${LDAP_BASE_DN}" "${LDAP_CERT_ATTR}" "${LDAP_BINDDN}" "${LDAP_BIND_PASS}" "${LDAP_USER_SEARCH}" "${LDAP_USER_CERT_CACHE_MAX_AGE}" "${CACHE_DIR}" "${SSH_PUBKEY_COMMENT}"  "${OCSP_ENABLE}" "${USER_CERT_ISSUER}" "${INTERMEDIATE_CA}" "${OCSP_RESPONDER}" "${CRL_URL}" "${INTERMEDIATE_CRL_URL}" "${CACERTS}" "${CACERTS_SHA512}" "${VALIDITY_PERIOD}")
  for option in "${options[@]}"; do
    if [ -z "${option:-}" ]; then
      return 1
    fi
  done
  return 0
}

error() {
  "${LOGGER}" -s -p ${LOGGER_ERR_FACILITY} -t ${LOGGER_ERR_TAG} "$*"
  exit 1
}

warn() {
  "${LOGGER}" -s -p ${LOGGER_WARN_FACILITY} -t ${LOGGER_WARN_TAG} "$*"
}

info() {
  "${LOGGER}" -s -p ${LOGGER_INFO_FACILITY} -t ${LOGGER_INFO_TAG} "$*"
}
