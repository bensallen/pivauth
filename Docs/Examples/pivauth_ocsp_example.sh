#!/bin/bash

# Older versions of OpenSSH do not allow for arguments to be specified in the AuthorizedKeysCommand setting.
# This script is a workaround to allow the configuration file to be specified.
/usr/sbin/pivauth ocsp_example "$@"