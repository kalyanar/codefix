# fix(security): BOLA in update_password — broken object level authorization

## exploit-verified fix · BOLA · ownership guard
- [x] exploit blocked on patched endpoint
- [x] legitimate path preserved (differential)
- [x] response contract holds
- [x] adversarial variant blocked

```diff
--- a/api_views/users.py
+++ b/api_views/users.py
@@ -7,6 +7,7 @@
 from flask import jsonify, Response, request, json
 from models.user_model import User
 from app import vuln
+from flask import abort
 
 
 def error_message_helper(msg):
@@ -185,6 +186,8 @@
         if request_data.get('password'):
             if vuln:  # Unauthorized update of password of another user
                 user = User.query.filter_by(username=username).first()
+                if user is not None and user.username != resp['sub']:
+                    abort(403)
                 if user:
                     user.password = request_data.get('password')
                     db.session.commit()
```

`BOLA` in `vampi::update_password` — broken object level authorization. The reproducer
`live pw-takeover reproducer` succeeds before this patch and is blocked after it; each box
above is an executed check against a sandboxed copy of the code.

- source: exact template (memory)
- selection posterior: 0.500

> verified by codefix · fingerprint: bola/flat/ownership (b172f1fb4fdbcea9)
