# fix(security): BOLA in get_by_title — broken object level authorization

## exploit-verified fix · BOLA · ownership guard
- [x] exploit blocked on patched endpoint
- [x] legitimate path preserved (differential)
- [x] response contract holds
- [x] adversarial variant blocked

```diff
--- a/api_views/books.py
+++ b/api_views/books.py
@@ -7,6 +7,7 @@
 from models.user_model import User
 from models.books_model import Book
 from app import vuln
+from flask import abort
 
 
 def get_all_books():
@@ -49,6 +50,8 @@
     else:
         if vuln:  # Broken Object Level Authorization
             book = Book.query.filter_by(book_title=str(book_title)).first()
+            if book is not None and book.user.username != resp['sub']:
+                abort(403)
             if book:
                 responseObject = {
                     'book_title': book.book_title,
```

`BOLA` in `vampi::get_by_title` — broken object level authorization. The reproducer
`live books-read reproducer` succeeds before this patch and is blocked after it; each box
above is an executed check against a sandboxed copy of the code.

- source: exact template (memory)
- selection posterior: 0.500

> verified by codefix · fingerprint: bola/flat/ownership (b172f1fb4fdbcea9)
