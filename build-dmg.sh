#!/bin/bash
# ============================================================================
# CROCbox DMG Builder
# Run from: ~/opnli/crocbox/
# Usage: bash build-dmg.sh
# ============================================================================

set -e

APP_NAME="CROCbox"
VERSION="0.6.1"
BUNDLE_ID="com.opnli.crocbox"
DMG_NAME="${APP_NAME}-v${VERSION}.dmg"
NODE_VERSION="0.6.1"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
APP_DIR="${BUILD_DIR}/${APP_NAME}.app"
CONTENTS="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS}/MacOS"
RESOURCES="${CONTENTS}/Resources"
APP_RESOURCES="${RESOURCES}/app"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   CROCbox DMG Builder v${VERSION}        ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# ── Step 1: Clean and create bundle structure ────────────────────────────────
echo "  [1/8] Creating app bundle structure..."
rm -rf "${BUILD_DIR}"
mkdir -p "${MACOS_DIR}"
mkdir -p "${RESOURCES}"
mkdir -p "${APP_RESOURCES}"

# ── Step 2: Node.js universal binary ────────────────────────────────────────
echo "  [2/8] Preparing embedded Node.js ${NODE_VERSION}..."
NODE_CACHE="${SCRIPT_DIR}/build-cache/node"

if [ ! -f "${NODE_CACHE}" ]; then
  mkdir -p "${SCRIPT_DIR}/build-cache"

  echo "        Downloading Node.js arm64..."
  curl -sL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-darwin-arm64.tar.gz" \
    -o /tmp/node-arm64.tar.gz
  tar -xzf /tmp/node-arm64.tar.gz -C /tmp/

  echo "        Downloading Node.js x64..."
  curl -sL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-darwin-x64.tar.gz" \
    -o /tmp/node-x64.tar.gz
  tar -xzf /tmp/node-x64.tar.gz -C /tmp/

  echo "        Creating universal binary..."
  lipo -create \
    -output "${NODE_CACHE}" \
    "/tmp/node-v${NODE_VERSION}-darwin-arm64/bin/node" \
    "/tmp/node-v${NODE_VERSION}-darwin-x64/bin/node"
  echo "        Cached at ${NODE_CACHE}"
else
  echo "        Using cached Node.js binary."
fi

cp "${NODE_CACHE}" "${RESOURCES}/node"
chmod +x "${RESOURCES}/node"

# ── Step 3: Copy application files ──────────────────────────────────────────
echo "  [3/8] Copying application files..."
cp -r "${SCRIPT_DIR}/src"           "${APP_RESOURCES}/src"
cp -r "${SCRIPT_DIR}/dashboard"     "${APP_RESOURCES}/dashboard"
cp    "${SCRIPT_DIR}/package.json"  "${APP_RESOURCES}/package.json"

if [ ! -d "${SCRIPT_DIR}/node_modules" ]; then
  echo "  ERROR: node_modules not found. Run 'npm install' first."
  exit 1
fi
cp -r "${SCRIPT_DIR}/node_modules"  "${APP_RESOURCES}/node_modules"

# Write .env.defaults — placeholders get replaced at first launch
# Update VERIFY_CARD_URL and keys here when Directive 3 (Owned Supabase) is complete
cat > "${APP_RESOURCES}/.env.defaults" << 'ENVEOF'
OPENCLAW_HOST=127.0.0.1
OPENCLAW_PORT=18789
CROCBOX_PROXY_PORT=18790
CROCBOX_GATEWAY_PORT=18791
CROCBOX_DASHBOARD_PORT=3000
CROCBOX_CONSENT_TIMEOUT=300000
VERIFY_CARD_URL=https://ehsnrqjyvtluwkmizsyy.supabase.co/functions/v1/verify-card
VERIFY_API_KEY=da1ec57bdb55e55068f9722fd1cd195f1df62466205eff5cfce408ff089297a4
SUPABASE_URL=https://ehsnrqjyvtluwkmizsyy.supabase.co
SUPABASE_ANON_KEY=sb_publishable_ku9GsVckF8Lpk_JiPstDzg_rYXedkdz
CROCBOX_LOG_DIR=SUPPORT_DIR_PLACEHOLDER/logs
CROCBOX_AGENT_ID=urn:uuid:5b3a4df1-d71b-4e8c-9c6d-22f12a95c358
ENVEOF

echo "        Application files copied."

# ── Step 4: Info.plist ───────────────────────────────────────────────────────
echo "  [4/8] Writing Info.plist..."
cat > "${CONTENTS}/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
  <key>CFBundleName</key><string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key><string>CROCbox</string>
  <key>CFBundleExecutable</key><string>${APP_NAME}</string>
  <key>CFBundleIconFile</key><string>CROCbox</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSArchitecturePriority</key>
  <array><string>arm64</string><string>x86_64</string></array>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSAllowsLocalNetworking</key><true/></dict>
</dict>
</plist>
PLIST

# ── Step 5: Launcher script ──────────────────────────────────────────────────
echo "  [5/8] Writing launcher script..."
cat > "${MACOS_DIR}/${APP_NAME}" << 'LAUNCHER'
#!/bin/bash
MACOS_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$(dirname "${MACOS_DIR}")/Resources"
APP_DIR="${RESOURCES_DIR}/app"
NODE="${RESOURCES_DIR}/node"

SUPPORT_DIR="${HOME}/Library/Application Support/CROCbox"
LOG_DIR="${SUPPORT_DIR}/logs"
PID_DIR="${SUPPORT_DIR}/pids"
ENV_FILE="${SUPPORT_DIR}/.env"

mkdir -p "${SUPPORT_DIR}" "${LOG_DIR}" "${PID_DIR}"

# Create .env on first launch
if [ ! -f "${ENV_FILE}" ]; then
  sed "s|SUPPORT_DIR_PLACEHOLDER|${SUPPORT_DIR}|g" \
    "${APP_DIR}/.env.defaults" > "${ENV_FILE}"
fi

show_error() {
  osascript -e "display dialog \"$1\" with title \"CROCbox\" buttons {\"Quit\"} default button \"Quit\" with icon stop"
  exit 1
}

port_in_use() { lsof -ti:$1 > /dev/null 2>&1; }

for PORT in 18790 18791 3000; do
  if port_in_use $PORT; then
    show_error "CROCbox cannot start: port $PORT is already in use. Please quit any other CROCbox instance and try again."
  fi
done

# Load .env
set -a; source "${ENV_FILE}"; set +a
export CROCBOX_LOG_DIR="${LOG_DIR}"

# Start CARD Proxy
cd "${APP_DIR}"
"${NODE}" -e "require('dotenv').config({path:'${ENV_FILE}'}); const {start}=require('./src/proxy/index.js'); start();" \
  > "${LOG_DIR}/proxy.log" 2>&1 &
echo $! > "${PID_DIR}/proxy.pid"

# Wait for proxy (up to 10s)
for i in $(seq 1 20); do
  sleep 0.5
  curl -s http://127.0.0.1:18790/crocbox/health > /dev/null 2>&1 && break
  if [ $i -eq 20 ]; then
    show_error "CROCbox could not start. See: ${LOG_DIR}/proxy.log"
  fi
done

# Start Gateway
"${NODE}" "${APP_DIR}/src/gateway/index.js" \
  > "${LOG_DIR}/gateway.log" 2>&1 &
echo $! > "${PID_DIR}/gateway.pid"

sleep 1

# Start Dashboard
"${NODE}" "${APP_DIR}/dashboard/server.js" \
  > "${LOG_DIR}/dashboard.log" 2>&1 &
echo $! > "${PID_DIR}/dashboard.pid"

sleep 1

# Open browser
open "http://127.0.0.1:3000"

# Cleanup on quit
cleanup() {
  for SVC in proxy gateway dashboard; do
    PID_FILE="${PID_DIR}/${SVC}.pid"
    [ -f "${PID_FILE}" ] && kill $(cat "${PID_FILE}") 2>/dev/null && rm "${PID_FILE}"
  done
  exit 0
}
trap cleanup SIGTERM SIGINT SIGHUP

# Stay alive and watch services
while true; do
  sleep 5
  for SVC in proxy gateway dashboard; do
    PID_FILE="${PID_DIR}/${SVC}.pid"
    if [ -f "${PID_FILE}" ]; then
      PID=$(cat "${PID_FILE}")
      if ! kill -0 $PID 2>/dev/null; then
        show_error "CROCbox service '${SVC}' stopped unexpectedly.\n\nSee: ${LOG_DIR}/${SVC}.log"
      fi
    fi
  done
done
LAUNCHER

chmod +x "${MACOS_DIR}/${APP_NAME}"

# ── Step 6: Icon ─────────────────────────────────────────────────────────────
echo "  [6/8] Copying icon..."
ICON_SRC="${SCRIPT_DIR}/assets/CROCbox.icns"
if [ -f "${ICON_SRC}" ]; then
  cp "${ICON_SRC}" "${RESOURCES}/CROCbox.icns"
  echo "        Icon copied."
else
  echo "        WARNING: No icon at assets/CROCbox.icns — app will use default icon."
fi

# ── Step 7: Code signing ─────────────────────────────────────────────────────
echo "  [7/8] Code signing..."
DEVELOPER_ID="6C6D004500B2F46397287F9AC20D7EFD1220A145"
# To enable signing, set DEVELOPER_ID to your certificate name, e.g.:
# DEVELOPER_ID="Developer ID Application: Mike Ozburn (XXXXXXXXXX)"

if [ -n "${DEVELOPER_ID}" ]; then
  codesign --deep --force --verify \
    --sign "${DEVELOPER_ID}" \
    --options runtime \
    "${APP_DIR}"
  echo "        Signed successfully."

  # Notarize if credentials are available
  if xcrun notarytool history --keychain-profile "notarytool-password" &>/dev/null; then
    echo "        Submitting for notarization..."
    ditto -c -k --keepParent "${APP_DIR}" "${BUILD_DIR}/${APP_NAME}.zip"
    xcrun notarytool submit "${BUILD_DIR}/${APP_NAME}.zip" \
      --keychain-profile "notarytool-password" \
      --wait
    xcrun stapler staple "${APP_DIR}"
    rm -f "${BUILD_DIR}/${APP_NAME}.zip"
    echo "        Notarization complete."
  else
    echo "        Notarization skipped — run 'xcrun notarytool store-credentials' to enable."
  fi
else
  echo "        Skipped — no Developer ID set."
  echo "        Users will need to right-click > Open on first launch."
fi

# ── Step 8: DMG ──────────────────────────────────────────────────────────────
echo "  [8/8] Creating DMG..."
DMG_STAGING="${BUILD_DIR}/dmg-staging"
mkdir -p "${DMG_STAGING}"
cp -r "${APP_DIR}" "${DMG_STAGING}/"
ln -s /Applications "${DMG_STAGING}/Applications"

hdiutil create \
  -volname "CROCbox v${VERSION}" \
  -srcfolder "${DMG_STAGING}" \
  -ov \
  -format UDZO \
  "${BUILD_DIR}/${DMG_NAME}"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   Build complete!                   ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
echo "  DMG: ${BUILD_DIR}/${DMG_NAME}"
echo ""
