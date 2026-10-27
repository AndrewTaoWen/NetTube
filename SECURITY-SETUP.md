# Security deployment changes

Set FIREBASE_PROJECT_ID to the Firebase client project's ID. Google sign-in now sends a Firebase ID token and verifies it using the Firebase Admin SDK. A submitted email alone cannot authenticate. Existing Google accounts need a trusted migration to populate firebaseUid; automatic linking by email is intentionally rejected. Password account linking must reauthenticate the original owner.

Set JWT to a new random secret of at least 32 bytes; this invalidates existing sessions. Sessions now expire after one hour and production cookies require HTTPS. Configure MONGO as before. Use Node 22 or newer.

Profile updates allow only name and image changes; password changes need a separate flow that verifies the old password and hashes the replacement. User responses no longer expose password hashes. Video ownership and engagement fields cannot be supplied through create/update payloads.

The unused legacy mongodb 2 driver is removed; database access continues through mongoose.
