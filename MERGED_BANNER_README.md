# Raven Info + Banner (Cyber Node)

## Browser UI
Open `/` for the black cyber-punk themed interface. Enter UID + API key once. The UI calls `/uc-main` once with `format=json`, displays the pretty Raven JSON, and renders the banner from the same response without a second player lookup.

## Main endpoint
Browser navigation:
`/uc-main?uid=UID&key=RAM-SAGAR`

When opened directly in a browser, `/uc-main` returns a compact HTML result containing:
- Pretty player JSON
- The generated PNG rendered directly as an embedded image
- No banner URL/path is exposed for the browser view

For API clients, request JSON:
`/uc-main?uid=UID&key=RAM-SAGAR&format=json`

The JSON response contains `info` and `banner.mime_type` + `banner.base64` (the image bytes, not a URL/path).

## Existing endpoints
- `/uc-info?uid=UID&key=RAM-SAGAR`
- `/uc-banner?uid=UID&key=RAM-SAGAR`
- `/uc-banner` POST with `{ "data": <player-json> }`
