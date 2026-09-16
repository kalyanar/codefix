# crAPI defect (exact location)

Source of record: `vendor/` — the crAPI **workshop** service (Python/Django),
vendored from https://github.com/OWASP/crAPI `services/workshop` at VERSION
1.1.5 (Apache-2.0, see `vendor/LICENSE.md`). crAPI is a multi-language stack;
codefix's Python detector applies to this workshop service, which owns the
shop-order endpoint. All other services (identity[Java], community[Go], gateway,
web, postgres, mongo, mailhog, chatbot, chromadb) run stock from published,
multi-arch (arm64-capable) images.

crAPI ships **no "secure" variant** — the app is always vulnerable. The live
harness (`run_crapi.py`) therefore establishes ground truth on the stock image,
then rebuilds ONLY the workshop image from `--patched-src` and swaps just that one
container in (the DB and every other service stay up), so a passing "after" is a
real code fix to the workshop service.

---

## Defect — shop-order BOLA (order + payment card leak)

- **File / class / method:** `vendor/crapi/shop/views.py` →
  `OrderControlView.get(self, request, order_id=None, user=None)`
- **Defect line:** the method definition at **views.py:109** and the unguarded
  fetch at **views.py:122**:
  ```python
  def get(self, request, order_id=None, user=None):   # 109  (NO @jwt_auth_required)
      order = Order.objects.get(id=order_id)           # 122  (no ownership check)
      ...
      response_data = dict(order=order_serializer.data, payment=payment)  # 164
  ```
  Two problems, unlike the sibling `post` (guarded at 167) and `put` (guarded at
  218, which also checks `if user != order.user`):
  1. **No `@jwt_auth_required`** decorator on `get` (line 109).
  2. **No object-ownership check** — the order is fetched by `order_id` alone
     (line 122) and returned to any caller, including the victim's payment card
     record (`payment.card_number`, `card_owner_name`, `card_type`,
     `card_expiry`) fetched from the payment gateway.
- **Endpoint:** `GET /workshop/api/shop/orders/<order_id>`
- **What a correct fix looks like:** add `@jwt_auth_required` on `get`, then
  enforce ownership immediately after the fetch, exactly like `put`/`ReturnOrder`
  already do (`views.py:236`, `315`):
  ```python
  @jwt_auth_required
  def get(self, request, order_id=None, user=None):
      order = Order.objects.get(id=order_id)
      if user != order.user:
          return Response({"message": messages.RESTRICTED},
                          status=status.HTTP_403_FORBIDDEN)
      ...
  ```
  Preserve the owner's legit response schema: `order` (id, user{email,number},
  product{id,name,price,image_url}, quantity, status, transaction_id, created_on)
  and the `payment` card record.
- **Reproducers:** exploit `exploit.py`, legit `legit.py`, adversarial
  `adversarial.py` (varied attacker: `alice_`/`mallory_` emails, different
  product/order, extra query + header).

Note on the leak: crAPI's payment gateway returns the PAN masked to the last four
digits (e.g. `XXXXXXXXXXXX8605`) alongside the card owner name, card type, and
expiry — i.e. the victim's full payment card *record* minus the middle PAN
digits. That is the real behaviour of the reference app.

---

## Validator stages

`run_crapi.py --patched-src DIR` runs, against the live stack:

| stage        | check |
|--------------|-------|
| exploit      | attacker path SUCCEEDS on the stock workshop (before) and is BLOCKED after the swap |
| differential | the legit owner path still reads its own order after the swap |
| contract     | the owner's legit `order`+`payment` response keeps its keys + value types (incl. the card record) |
| adversarial  | a *varied* attacker (different user / object / request shape) is also blocked |

A reference GOOD patch passes all four. Two deliberately bad patches are each
caught by exactly one stage: a field-strip fix (drops `payment.card_number`)
fails **contract**; a narrow victim-specific fix fails **adversarial**.
