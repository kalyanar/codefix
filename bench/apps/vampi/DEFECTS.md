# VAmPI defects (exact locations)

Source of record: `vendor/` (an unmodified copy of https://github.com/erev0s/VAmPI).
VAmPI serves a vulnerable or "secure" variant off one code base, switched by the
`vuln` flag (`vendor/app.py:9`, `vuln = int(os.getenv('vulnerable', 1))`). Both
defects below live in the `if vuln:` branch of one function.

The live harness (`run_vampi.py`) does NOT flip that flag to show a fix: it runs
BOTH containers with `vulnerable=1` and swaps only the *code*, so a passing
"after" is a real code fix, not VAmPI's secure toggle.

---

## Defect 1 — books-read BOLA (object-read secret leak)

- **File / function:** `vendor/api_views/books.py` → `get_by_title(book_title)`
- **Vulnerable branch:** `if vuln:` at **books.py:50**
- **Root cause line:** **books.py:51**
  ```python
  book = Book.query.filter_by(book_title=str(book_title)).first()
  ```
  The lookup is keyed on `book_title` only — there is **no owner scope**, so any
  authenticated user can read any other user's book, including `secret_content`
  (`books.py:53-58` returns `book_title`, `secret`, `owner`).
- **Endpoint:** `GET /books/v1/<book_title>`
- **What a correct fix looks like:** scope the query to the authenticated caller
  (`resp['sub']`), exactly as VAmPI's own else-branch already does at
  **books.py:62-63**:
  ```python
  user = User.query.filter_by(username=resp['sub']).first()
  book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
  ```
  The response schema must be preserved: `{book_title: str, secret: str, owner: str}`.
- **Reproducers:** exploit `exploit.py`, legit `legit.py`, adversarial `adversarial.py`
  (varied attacker: `alice_`/`mallory_` users, `journal_` title, extra query + header).

## Defect 2 — password-takeover BOLA (account takeover)

- **File / function:** `vendor/api_views/users.py` → `update_password(username)`
- **Vulnerable branch:** `if vuln:` at **users.py:186**
- **Root cause line:** **users.py:187**
  ```python
  user = User.query.filter_by(username=username).first()
  ```
  The target user is taken from the **URL path** (`<username>`), not from the
  authenticated token, so an attacker sets any other user's password
  (`users.py:189-190`) and takes over the account.
- **Endpoint:** `PUT /users/v1/<username>/password`
- **What a correct fix looks like:** update only the caller's own row, as VAmPI's
  else-branch does at **users.py:194**:
  ```python
  user = User.query.filter_by(username=resp['sub']).first()
  user.password = request_data.get('password')
  ```
  Preserve the success contract: HTTP `204` with `{status: "success", Password: "Updated."}`.
- **Reproducers:** exploit `exploit_pw.py`, legit `legit_pw.py`, adversarial `adversarial_pw.py`.

---

## Validator stages (both defects)

`run_vampi.py --patched-src DIR` runs, per defect:

| stage        | check |
|--------------|-------|
| exploit      | attacker path SUCCEEDS on :5002 (before) and is BLOCKED on :5001 (after) |
| differential | the legit owner path still works on :5001 |
| contract     | the owner's legit response keeps the expected keys + value types |
| adversarial  | a *varied* second attacker (different user / object / request shape) is also blocked |

A reference GOOD patch (owner-scoped `get_by_title`, token-scoped
`update_password`) passes all four for both defects. Two deliberately bad patches
are each caught by exactly one stage: a field-strip fix (drops `owner`) fails
**contract**; a narrow victim-specific fix fails **adversarial**.
