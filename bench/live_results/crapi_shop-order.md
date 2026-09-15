# fix(security): BOLA in get — broken object level authorization

## exploit-verified fix · BOLA · ownership guard
- [x] exploit blocked on patched endpoint
- [x] legitimate path preserved (differential)
- [x] response contract holds
- [x] adversarial variant blocked

```diff
--- a/crapi/shop/views.py
+++ b/crapi/shop/views.py
@@ -106,6 +106,7 @@
     Order Controller View
     """
 
+    @jwt_auth_required
     def get(self, request, order_id=None, user=None):
         """
         order view for fetching  a particular order
@@ -120,6 +121,10 @@
             message and corresponding status if error
         """
         order = Order.objects.get(id=order_id)
+        if user != order.user:
+            return Response(
+                {"message": messages.RESTRICTED}, status=status.HTTP_403_FORBIDDEN
+            )
         order_serializer = OrderSerializer(order)
         user = order.user
         # email user.email, number user.number
```

`BOLA` in `crapi::get` — broken object level authorization. The reproducer
`live shop-order reproducer` succeeds before this patch and is blocked after it; each box
above is an executed check against a sandboxed copy of the code.

- source: exact template (memory)
- selection posterior: 0.500

> verified by codefix · fingerprint: bola/flat/ownership (06aa1d74503da1e0)
