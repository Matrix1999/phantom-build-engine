---
name: Cloud source asset IDs
description: Correct identifier type for dispatching complete project archives to the remote APK builder.
---

When dispatching a release-hosted source archive to the cloud APK builder, pass the release asset's numeric REST `id`, never its GraphQL node ID beginning with `RA_`.

**Why:** The workflow downloads through GitHub's REST release-assets endpoint. A GraphQL node ID makes that endpoint return an error response, which is then saved as the source ZIP and fails extraction with a misleading invalid-ZIP error.

**How to apply:** Resolve the asset through the REST release API and validate that the selected ID contains digits only before dispatching the workflow.