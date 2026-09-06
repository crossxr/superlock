# SuperLock — Test Guide

No automated unit tests in Phase 1. Follow these manual steps to verify all features.

---

## Prerequisites

- Backend running locally (`go run ./cmd/server`) or deployed
- Frontend running locally (`npm run dev`) or deployed
- Backend URL noted (e.g., `http://localhost:8080`)
- Frontend open in browser (e.g., `http://localhost:3000`)

---

## Test 1: Health Check

```bash
curl http://localhost:8080/health
```

**Expected:**

```json
{ "status": "ok", "service": "superlock" }
```

---

## Test 2: Auth — Sign Up

1. Open `http://localhost:3000`
2. You should be redirected to `/login`
3. Click **"Sign up"**
4. Enter an email and password (min 8 chars)
5. Click **Create account**

**Expected:** "Check your email" screen appears (or if email confirmation is disabled in Supabase, you can sign in directly).

If email confirmation is disabled in Supabase:

- Go back to `/login`
- Sign in with your new credentials
- **Expected:** Redirect to `/dashboard`

---

## Test 3: Onboarding — Create Organization

After first login, you should be redirected to `/onboarding`.

1. Enter an organization name (e.g., "My Team")
2. Click **Create organization**

**Expected:** Redirected to `/dashboard` with org name shown in the header.

If you are NOT redirected to onboarding after login, verify:

- The backend is running and `DATABASE_URL` is correct
- Check browser network tab for errors on `GET /v1/orgs/me`

---

## Test 4: Create a Project

1. Go to **Projects** in the sidebar
2. Click **New project**
3. Enter name: `payments-service`
4. Enter description: `Handles payment processing`
5. Click **Create project**

**Expected:**

- Project appears in the list with slug `payments-service`
- Three environments are auto-created: `development`, `staging`, `production`

---

## Test 5: View Project Environments

1. Click on the `payments-service` project
2. You should see three environment cards: development, staging, production
3. Production should show a lock icon (protected)

**Expected:** Three environment cards with correct colors (green/yellow/red).

---

## Test 6: Add Secrets

1. Click on the **development** environment
2. Click **Add secret**
3. Enter Key: `DATABASE_URL`
4. Enter Value: `postgres://localhost:5432/mydb`
5. Click **Add secret**

**Expected:** Secret appears in the list with key `DATABASE_URL` and version `v1`.

Add a second secret:

- Key: `API_KEY`
- Value: `sk_test_abc123`

---

## Test 7: Reveal & Copy a Secret

1. On the secrets list, click the **eye icon** on `DATABASE_URL`
2. The value should appear below the key in green monospace text

**Expected:** `postgres://localhost:5432/mydb` is displayed.

3. Click the **copy icon** on `DATABASE_URL`

**Expected:** Clipboard contains the value (verify by pasting).

---

## Test 8: Edit a Secret

1. Click the **pencil icon** on `API_KEY`
2. Change the value to `sk_test_xyz999`
3. Click **Save**

**Expected:**

- Secret saves successfully
- Version increments to `v2` (visible when you expand the row with the chevron)

---

## Test 9: Search Secrets

1. Type `DATA` in the search box
2. **Expected:** Only `DATABASE_URL` is visible, `API_KEY` is filtered out

---

## Test 10: Delete a Secret

1. Click the **trash icon** on `API_KEY`
2. Confirm in the dialog

**Expected:** `API_KEY` disappears from the list.

---

## Test 11: Protected Environment (production)

1. Go back to the project page
2. Click on the **production** environment
3. Try adding a secret

**Expected (if your role is owner):** You can add secrets.
**Expected (if your role is reader/developer):** You get a 403 error.

---

## Test 12: Create a Custom Environment

1. Go to the project page for `payments-service`
2. Click **New environment**
3. Name: `preview`
4. Leave "Protected" unchecked
5. Click **Create**

**Expected:** A new `preview` environment card appears.

---

## Test 13: API Tokens

1. Go to **API Tokens** in the sidebar
2. Click **New token**
3. Name: `GitHub Actions`
4. Leave scopes as `secrets:read`
5. Click **Create token**

**Expected:**

- A green banner appears showing the full token (`superlock_XXXX...`)
- Copy the token immediately (it won't be shown again)

Test the token via curl:

```bash
# Replace with your token and environment ID (get eid from the URL when viewing secrets)
curl -H "Authorization: Bearer superlock_YOUR_TOKEN_HERE" \
  http://localhost:8080/v1/envs/YOUR_ENV_ID/secrets/values
```

**Expected:** A JSON object with all secret key-value pairs for that environment.

---

## Test 14: Audit Log

1. Go to **Audit Log** in the sidebar
2. You should see events for all the actions performed:
   - `org.created`
   - `project.created`
   - `secret.write`
   - `secret.read`
   - `secret.delete`
   - `token.created`

3. Use the **Action filter** to filter by `secret.read`

**Expected:** Only read events are shown.

---

## Test 15: Revoke an API Token

1. Go to **API Tokens**
2. Click the trash icon on `GitHub Actions`
3. Confirm in the dialog

**Expected:** Token disappears from the list.

Test that the revoked token no longer works:

```bash
curl -H "Authorization: Bearer superlock_YOUR_OLD_TOKEN" \
  http://localhost:8080/v1/projects
```

**Expected:** `401 Unauthorized`

---

## Test 16: Backend API Direct Tests

Test the REST API directly with curl (get your JWT from browser devtools → Application → Local Storage → `sb-xxx-auth-token`):

```bash
TOKEN="eyJ..."  # Your Supabase JWT

# List projects
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/projects

# Get current org
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/orgs/me

# Get current user
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/me
```

---

## Test 17: Sign Out

1. Click the **logout icon** at the bottom of the sidebar
2. **Expected:** Redirected to `/login`
3. Try accessing `http://localhost:3000/dashboard`
4. **Expected:** Redirected to `/login` (auth guard working)

---

## Common Issues

| Issue                                  | Fix                                                                                                                                                 |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ENCRYPTION_KEY: invalid KEK encoding` | Key must be exactly 32 bytes base64-encoded. Run `openssl rand -base64 32`                                                                          |
| 401 on all API calls                   | Check `SUPABASE_URL` is correct so JWKS can be fetched, and restart backend after env changes. For legacy HS256 projects, set `SUPABASE_JWT_SECRET` |
| `DB ping failed`                       | Check `DATABASE_URL` format — use transaction pooler URL (port 6543) from Supabase                                                                  |
| CORS errors in browser                 | Add your frontend URL to `ALLOWED_ORIGINS` in the backend                                                                                           |
| Dashboard shows blank after login      | Backend may not be running, check `NEXT_PUBLIC_API_URL`                                                                                             |
| Email confirmation loop                | Disable email confirmation in Supabase Auth settings for development                                                                                |
