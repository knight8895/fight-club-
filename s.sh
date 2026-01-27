#!/usr/bin/env bash
set -e

echo "♻️ Updating Vercel PRODUCTION env vars (idempotent)..."

add_or_update () {
  NAME="$1"
  VALUE="$2"
  SENSITIVE="$3"

  vercel env rm "$NAME" production --yes >/dev/null 2>&1 || true

  if [ "$SENSITIVE" = "true" ]; then
    echo "$VALUE" | vercel env add "$NAME" production --yes --sensitive
  else
    echo "$VALUE" | vercel env add "$NAME" production --yes
  fi
}

add_or_update NODE_ENV "production" false
add_or_update PORT "3000" false
add_or_update FRONTEND_URL "https://fight-club-frontend.vercel.app" false

add_or_update JWT_SECRET "c088e19f99b5cde5057c7aafc31bee267e0041a22b9d42a246df3d8c3b25cbf37005f715e44d4713a7125f3aee378f390308b3138d3be4fad0becb1979504430" true

add_or_update FIREBASE_PROJECT_ID "rgma-arena" false
add_or_update FIREBASE_PRIVATE_KEY_ID "d770029b05e3673140547604113f028b1485550a" true

add_or_update FIREBASE_PRIVATE_KEY "$(cat <<'EOF'
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCv3n+MTFYBURLC
DO9i7ywsCtZ/6BrXhXYCJw2BS92kGWy26+Y2r49JQ6nv2MKBHRZj6c2igwUkC7RT
...
VVMB45kY=
-----END PRIVATE KEY-----
EOF
)" true

add_or_update FIREBASE_CLIENT_EMAIL "firebase-adminsdk-fbsvc@rgma-arena.iam.gserviceaccount.com" false
add_or_update FIREBASE_CLIENT_ID "117957782412063670074" false
add_or_update FIREBASE_CERT_URL "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40rgma-arena.iam.gserviceaccount.com" false
add_or_update FIREBASE_DATABASE_URL "https://rgma-arena-default-rtdb.asia-southeast1.firebasedatabase.app" false
add_or_update FIREBASE_STORAGE_BUCKET "rgma-arena.firebasestorage.app" false

echo "✅ All production env vars updated successfully"
