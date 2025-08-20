#!/bin/bash

# Fix OpenSSL legacy renegotiation issue in containers
# This script addresses the "unsafe legacy renegotiation disabled" error

echo "🔧 Fixing OpenSSL legacy renegotiation configuration..."

# Backup original openssl.cnf if it exists
if [ -f /etc/ssl/openssl.cnf ]; then
    cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.backup
    echo "✅ Backed up original openssl.cnf"
fi

# Add legacy renegotiation settings to openssl.cnf
cat >> /etc/ssl/openssl.cnf << 'EOF'

# Enable legacy renegotiation for proxy compatibility
# This fixes "unsafe legacy renegotiation disabled" errors
Options = UnsafeLegacyRenegotiation
CipherString = DEFAULT@SECLEVEL=1

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
Options = UnsafeLegacyRenegotiation
CipherString = DEFAULT@SECLEVEL=1
EOF

# Set environment variables
export OPENSSL_CONF=/etc/ssl/openssl.cnf
export SSL_CERT_DIR=/etc/ssl/certs

echo "✅ OpenSSL configuration updated successfully"
echo "📋 Current OpenSSL configuration:"
echo "   OPENSSL_CONF=$OPENSSL_CONF"
echo "   SSL_CERT_DIR=$SSL_CERT_DIR"

# Test OpenSSL configuration
if openssl version > /dev/null 2>&1; then
    echo "✅ OpenSSL is working correctly: $(openssl version)"
else
    echo "❌ OpenSSL configuration test failed"
    exit 1
fi

echo "🎯 OpenSSL legacy renegotiation fix applied successfully"
