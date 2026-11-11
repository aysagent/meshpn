#!/usr/bin/env bash
# Local build only. Does not access projectors, VPSs or host network settings.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if [ -z "${JAVA_HOME:-}" ] && [ -x '/Applications/IntelliJ IDEA CE.app/Contents/jbr/Contents/Home/bin/java' ]; then
  export JAVA_HOME='/Applications/IntelliJ IDEA CE.app/Contents/jbr/Contents/Home'
fi
if [ -z "${ANDROID_HOME:-}" ] && [ -d "$PWD/.tools/sdk" ]; then
  export ANDROID_HOME="$PWD/.tools/sdk"
fi
: "${ANDROID_HOME:?Set ANDROID_HOME to your Android SDK directory (see README.md)}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$PWD/.tools/gradle-home}"
for cvpn_tool in cmake git patch; do command -v "$cvpn_tool" >/dev/null || { echo "Missing: $cvpn_tool" >&2; exit 1; }; done
umask 077
mkdir -p .tools/signing
if [ ! -e .tools/signing/release.p12 ] && [ ! -e .tools/signing/password ]; then
  command -v openssl >/dev/null
  openssl rand -hex 32 > .tools/signing/password
  "${JAVA_HOME:+$JAVA_HOME/bin/}keytool" -genkeypair -keystore .tools/signing/release.p12 \
    -storetype PKCS12 -storepass:file .tools/signing/password -keypass:file .tools/signing/password \
    -alias clean-vpn -keyalg RSA -keysize 3072 -validity 10000 -dname 'CN=Clean VPN local APK' -noprompt
fi
if [ ! -s .tools/signing/release.p12 ] || [ ! -s .tools/signing/password ]; then
  echo 'Incomplete signing directory. Restore both release.p12 and password; do not replace a deployed signing key.' >&2
  exit 1
fi
# Configure the shared, pinned BoringSSL source and apply the repository patches.
# This does not build the old helper and never modifies installed VPN services.
cmake -S ../native/boring_tls -B .tools/deps -DCMAKE_BUILD_TYPE=Release
./gradlew --console=plain :app:assembleRelease :app:testDebugUnitTest :app:lintRelease
printf '\nAPK: %s/app/build/outputs/apk/release/app-release.apk\n' "$PWD"
