---
name: Cloud build dispatch — phantom-build-engine
description: GitHub repo and workflow IDs for dispatching builds
---

## Repo
`Matrix1999/phantom-build-engine`

## Workflow IDs
| Workflow | ID |
|---|---|
| `build.yml` (Universal APK Builder) | 328899541 |
| `build-libphantom.yml` | 328870953 |
| `build-libcipher.yml` | 329294877 |
| `build-ndk.yml` | 329635593 |

## Dispatch pattern for build.yml
Required inputs: `app_name`, `package_name`, `job_id`, `asset_id`
- Upload source ZIP as a GitHub release asset first → get asset_id
- Dispatch with `ref: main`
- APK artifact named `apk-{job_id}`, 1-day retention

## Package name
`com.ultra.dex2cvmp` (Ultra Dex2c VMP protector app itself)
