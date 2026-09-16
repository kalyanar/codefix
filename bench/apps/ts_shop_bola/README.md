# ts_shop_bola — the engine on a SCIP-indexed TypeScript codebase

The same BOLA as `shop_multifile`, written in TypeScript across four modules.
`vuln/` has no ownership check, `safe/` has a dominating one, and `skippable/`
puts the check inside a branch that can be skipped. Each variant carries the
`index.scip` produced by scip-typescript; `codefix.scip.build_from_scip` turns it
into a CallGraphProvider and the unchanged engine runs over it.

Regenerate the indexes (needs Node):

    npm install --prefix /tmp/sciptools @sourcegraph/scip-typescript typescript
    for v in vuln safe skippable; do
      (cd $v && /tmp/sciptools/node_modules/.bin/scip-typescript index --output index.scip)
    done
