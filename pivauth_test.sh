#!/bin/bash

. functions.sh

# Allowed time skew on OCSP revocation checks
VALIDITY_PERIOD=3600

fail() {
  echo "TEST $*: FAILED"
  exit 1
}

success() {
  echo "TEST $*: SUCCEEDED"
}

run_test() {
  local run_func=${1}
  local name=${2}
  local expect_rc=${3}
  shift 3

  ${run_func} "$@"
  if [ "${expect_rc}" -eq $? ]; then
    success "${name}"
  else
    fail "${name}"
  fi
}

run_test validate_username "validate_username - Empty Arg" 2 ''
run_test validate_username "validate_username - Valid" 0 'root'
run_test validate_username "validate_username - Non-existent" 1 'doesnotexist'
run_test validate_username "validate_username - Invalid Charecters" 1 'johnny;drop database'

# Test validate_ca_checksum
CACERTS_SHA512_GOOD="0de66daacc2ac15e4285b0080572c566598fce05ceff317e85efe1540128a01d50a5fe1e7a95d3d5dba195ef965799c87a3708c4a111a73fe59765e049dda17f  Tests/CA/NIST/RSA2048CA.pem"

CACERTS_SHA512_BAD="0114d4e09c9516a68eaa878b128973748307f1d1297e6949c709c733512518f2b546f46eab283ec40b85960b7d0f2672050869198d28e28a9ff783266f2c54c5  Tests/CA/NIST/RSA2048CA.pem"

run_test validate_ca_checksum "validate_ca_checksum - Empty Arg" 2 "" 
run_test validate_ca_checksum "validate_ca_checksum - Valid" 0 "${CACERTS_SHA512_GOOD}" 
run_test validate_ca_checksum "validate_ca_checksum - Invalid" 1 "${CACERTS_SHA512_BAD}" 

# Test validate_cert_ca
run_test validate_cert_ca "validate_cert_ca - Empty Args" 2 "" ""
run_test validate_cert_ca "validate_cert_ca - Trusted" 0 Tests/good_user_cert.pem <(cat Tests/CA/NIST/*.pem)
run_test validate_cert_ca "validate_cert_ca - Trusted, but revoked cert" 0 Tests/revoked_user_cert.pem <(cat Tests/CA/NIST/*.pem)
run_test validate_cert_ca "validate_cert_ca - Not Trusted - No CAs" 1 Tests/good_user_cert.pem /dev/null

# Test validate_cert_ocsp
run_test validate_cert_ocsp "validate_cert_ocsp - Empty Args" 2 "" "" "" "" ""
run_test validate_cert_ocsp "validate_cert_ocsp - Check signing CA against intermediate" 0 CA/FPKI/entrustca.pem CA/FPKI/entrustssp.pem http://ocsp.managed.entrust.com/OCSP/EMSSSPCAResponder CA/FPKI/FederalCommonPolicyCA.pem "${VALIDITY_PERIOD}"
run_test validate_cert_ocsp "validate_cert_ocsp - Valid User Cert" 0 Tests/CA/NIST/RSA2048CA.pem Tests/good_user_cert.pem http://seclab7.ncsl.nist.gov Tests/CA/NIST/TrustAnchorCertificate.pem "${VALIDITY_PERIOD}"
run_test validate_cert_ocsp "validate_cert_ocsp - Revoked Cert" 1 Tests/CA/NIST/RSA2048CA.pem Tests/revoked_user_cert.pem http://seclab7.ncsl.nist.gov Tests/CA/NIST/TrustAnchorCertificate.pem "${VALIDITY_PERIOD}"
run_test validate_cert_ocsp "validate_cert_ocsp - Nonexistent URL" 3 Tests/CA/NIST/RSA2048CA.pem Tests/good_user_cert.pem http://example.com Tests/CA/NIST/TrustAnchorCertificate.pem "${VALIDITY_PERIOD}"

# Create temp cache dir for these tests
CACHE_DIR="$(mktemp -d)"

# Test fetch_crl
run_test fetch_crl "fetch_crl - Empty Args" 2 "" ""
run_test fetch_crl "fetch_crl - Valid" 0 "${CACHE_DIR}"/RSA2048CA.crl "http://smime2.nist.gov/PIVTest/RSA2048CA.crl"
rm -f "${CACHE_DIR}"/RSA2048CA.crl

# Test validate_cert_crl
run_test validate_cert_crl "validate_cert_crl - Empty Args" 2 "" "" ""
run_test validate_cert_crl "validate_cert_crl - Nonexistent Paths" 2 "does/not/exist/test.crl" "does/not/exist/ca.pem" "does/not/exist/user_cert.pem"
run_test validate_cert_crl "validate_cert_crl - Valid" 0 "Tests/CA/NIST/RSA2048CA.crl" <(cat Tests/CA/NIST/*.pem) "Tests/good_user_cert.pem"
run_test validate_cert_crl "validate_cert_crl - Revoked Cert" 1 "Tests/CA/NIST/RSA2048CA.crl" <(cat Tests/CA/NIST/*.pem) "Tests/revoked_user_cert.pem"

# Test check_cert_revocation
# Remove cached CRL (if it exists) between each test
run_test check_cert_revocation "check_cert_revocation - Empty Args" 2 "" "" "" "" "" "" ""
rm -f "${CACHE_DIR}"/RSA2048CA.crl
run_test check_cert_revocation "check_cert_revocation - Valid - OCSP Enabled" 0 Tests/CA/NIST/RSA2048CA.pem Tests/good_user_cert.pem http://seclab7.ncsl.nist.gov <(cat Tests/CA/NIST/*.pem) 1 http://smime2.nist.gov/PIVTest/RSA2048CA.crl "${VALIDITY_PERIOD}"
rm -f "${CACHE_DIR}"/RSA2048CA.crl
run_test check_cert_revocation "check_cert_revocation - Valid - OCSP Disabled" 0 Tests/CA/NIST/RSA2048CA.pem Tests/good_user_cert.pem http://seclab7.ncsl.nist.gov <(cat Tests/CA/NIST/*.pem) 0 http://smime2.nist.gov/PIVTest/RSA2048CA.crl "${VALIDITY_PERIOD}"
rm -f "${CACHE_DIR}"/RSA2048CA.crl
run_test check_cert_revocation "check_cert_revocation - Revoked Cert - OCSP Enabled" 1 Tests/CA/NIST/RSA2048CA.pem Tests/revoked_user_cert.pem http://seclab7.ncsl.nist.gov <(cat Tests/CA/NIST/*.pem) 1 http://smime2.nist.gov/PIVTest/RSA2048CA.crl "${VALIDITY_PERIOD}"
rm -f "${CACHE_DIR}"/RSA2048CA.crl
run_test check_cert_revocation "check_cert_revocation - Revoked Cert - OCSP Disabled" 1 Tests/CA/NIST/RSA2048CA.pem Tests/revoked_user_cert.pem http://seclab7.ncsl.nist.gov <(cat Tests/CA/NIST/*.pem) 0 http://smime2.nist.gov/PIVTest/RSA2048CA.crl "${VALIDITY_PERIOD}"
rm -f "${CACHE_DIR}"/RSA2048CA.crl
run_test check_cert_revocation "check_cert_revocation - Valid - OCSP Enabled - Bad OCSP URL" 0 Tests/CA/NIST/RSA2048CA.pem Tests/good_user_cert.pem http://example.com/OCSP/EMSSSPCAResponder <(cat Tests/CA/NIST/*.pem) 1 http://smime2.nist.gov/PIVTest/RSA2048CA.crl "${VALIDITY_PERIOD}"
rm -f "${CACHE_DIR}"/RSA2048CA.crl
run_test check_cert_revocation "check_cert_revocation - Valid - OCSP Enabled - Bad CRL URL" 0 Tests/CA/NIST/RSA2048CA.pem Tests/good_user_cert.pem http://seclab7.ncsl.nist.gov <(cat Tests/CA/NIST/*.pem) 1 http://example.com/PIVTest/RSA2048CA.crl "${VALIDITY_PERIOD}"
rm -f "${CACHE_DIR}"/RSA2048CA.crl
run_test check_cert_revocation "check_cert_revocation - Valid - OCSP Disabled - Bad CRL URL" 1 Tests/CA/NIST/RSA2048CA.pem Tests/good_user_cert.pem http://seclab7.ncsl.nist.gov <(cat Tests/CA/NIST/*.pem) 0 http://example.com/PIVTest/RSA2048CA.crl "${VALIDITY_PERIOD}"

rm -rf "${CACHE_DIR}"
unset CACHE_DIR

