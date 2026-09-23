# Releasing

Releases are automated by [`.github/workflows/release.yml`](../.github/workflows/release.yml). Pushing a version tag runs the tests, packages the extension, publishes it to the **VS Code Marketplace** and **Open VSX**, and creates a **GitHub release** with the `.vsix` attached and the matching `CHANGELOG.md` section as notes.

## One-time setup

1. **Marketplace publisher:** create one at https://marketplace.visualstudio.com/manage. Its ID must equal `"publisher"` in `package.json` (`carlsullivan11`).
2. **Marketplace token:** at https://dev.azure.com open **User settings → Personal access tokens → New token** and set:
   - Organization: **All accessible organizations**
   - Scopes: **Custom defined → Marketplace → Manage**
3. **Open VSX token:** sign in at https://open-vsx.org with GitHub, sign the publisher agreement, create an access token, then create the namespace once:
   ```bash
   npx ovsx create-namespace carlsullivan11 --pat <OVSX token>
   ```
4. **GitHub secrets:** add them under **Settings → Secrets and variables → Actions**:
   - `VSCE_PAT`: the Marketplace token
   - `OVSX_PAT`: the Open VSX token

   If a secret is missing, that registry is skipped with a warning and the GitHub release is still created.
5. **Optional approval gate:** the job runs in a GitHub environment named `release`, which is created on first use. To require manual approval before anything publishes, add yourself as a required reviewer under **Settings → Environments → release**. You can also store the two secrets there instead of at repository level.

Marketplace tokens expire (one year at most). When publishing fails with a 401, create a new token and update `VSCE_PAT`.

## Cutting a release

1. In `CHANGELOG.md`, rename `## Unreleased` to the new version (e.g. `## 0.3.0`) and commit it on `main`. The release notes are taken from that section.
2. Bump the version and push the tag:
   ```bash
   npm version minor          # or patch / major: updates package.json + package-lock.json, commits, tags v0.3.0
   git push --follow-tags
   ```
3. Watch the **Release** workflow in the Actions tab. The Marketplace listing updates a few minutes after it finishes.

The workflow fails early if the tag doesn't match `package.json`'s version, so always create tags with `npm version`.

### Pre-releases

A tag like `v0.3.0-beta.1` builds and creates a GitHub **pre-release** with the `.vsix`, but doesn't publish to the Marketplace or Open VSX, because the Marketplace rejects semver pre-release versions. Testers can install the file with `code --install-extension yaral-toolkit-0.3.0-beta.1.vsix`.

### Dry run

Run the **Release** workflow manually (**Actions → Release → Run workflow**). It builds, tests and packages, uploads the `.vsix` as an artifact, and publishes nothing.
