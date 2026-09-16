/**
 * @name Object lookup keyed by user input without an ownership check (BOLA attempt)
 * @description A best-effort, hand-authored attempt to find Broken Object Level
 *              Authorization with CodeQL's standard building blocks: global taint
 *              tracking from a RemoteFlowSource (the library's own notion of a
 *              routed request parameter / request data) into the key of an
 *              object lookup, where an ownership comparison acts as a
 *              BarrierGuard. This is NOT part of any CodeQL suite: it is the
 *              "CodeQL can express guard dominance via BarrierGuard" experiment
 *              for the codefix baselines (bench/baselines.py). It was written
 *              once, before looking at its results, and is not tuned per app.
 * @kind problem
 * @problem.severity error
 * @id codefix-baseline/py/bola-barrierguard
 * @tags security
 *       external/cwe/cwe-639
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

/**
 * Name heuristic for "the authenticated principal". Authorization is
 * application-specific, so there is no library notion of an owner; a generic
 * query has to guess from identifiers.
 */
bindingset[s]
predicate principalName(string s) {
  s.regexpMatch("(?i).*(user|owner|principal|identity|account|author|member|session|token|jwt|claim|uid).*")
}

/** Holds if expression `e` (or any sub-expression) names the principal. */
predicate mentionsPrincipal(Expr e) {
  exists(Expr sub | sub = e or sub = e.getASubExpression+() |
    principalName(sub.(Name).getId())
    or
    principalName(sub.(Attribute).getName())
  )
}

/**
 * The BarrierGuard: a comparison between the tracked value and something that
 * names the principal (`==`/`is`/`in` on the true branch, their negations on
 * the false branch), e.g. `if order_id in current_user.order_ids:`.
 */
predicate ownershipCompare(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {
  exists(CompareNode cn, Cmpop op, ControlFlowNode other | cn = g |
    (cn.operands(node, op, other) or cn.operands(other, op, node)) and
    mentionsPrincipal(other.getNode()) and
    (
      (op instanceof Eq or op instanceof Is or op instanceof In) and branch = true
      or
      (op instanceof NotEq or op instanceof IsNot or op instanceof NotIn) and branch = false
    )
  )
}

/** Method names of object lookups (dict, SQLAlchemy, Django ORM, Flask-SQLAlchemy). */
predicate lookupMethod(string name) {
  name in ["get", "get_or_404", "first_or_404", "filter", "filter_by", "exclude", "get_object_or_404"]
}

/** A call that looks an object up; `get_object_or_404(Model, pk=...)` included. */
DataFlow::CallCfgNode lookupCall() {
  lookupMethod(result.(DataFlow::MethodCallNode).getMethodName())
  or
  result.getFunction().asCfgNode().(NameNode).getId() = "get_object_or_404"
}

/** The lookup is already scoped to the principal, e.g. `filter(id=x, user=request.user)`. */
predicate principalScoped(DataFlow::CallCfgNode call) {
  mentionsPrincipal(call.getArg(_).asExpr()) or
  mentionsPrincipal(call.getArgByName(_).asExpr())
}

/** The looked-up object is later compared against the principal (post-fetch ownership check). */
predicate postFetchOwnershipCheck(DataFlow::CallCfgNode call) {
  exists(DataFlow::Node result_, DataFlow::Node use, CompareNode cn, Cmpop op,
    ControlFlowNode operand, ControlFlowNode other
  |
    // the lookup result, or the result of a chained call on it (`.first()`, `.one()`)
    (result_ = call or result_.(DataFlow::MethodCallNode).getObject() = call) and
    DataFlow::localFlow(result_, use) and
    (cn.operands(operand, op, other) or cn.operands(other, op, operand)) and
    (operand = use.asCfgNode() or operand.(AttrNode).getObject() = use.asCfgNode()) and
    mentionsPrincipal(other.getNode())
  )
}

module BolaConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call | call = lookupCall() |
      (sink = call.getArg(_) or sink = call.getArgByName(_)) and
      not principalScoped(call) and
      not postFetchOwnershipCheck(call)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::BarrierGuard<ownershipCompare/3>::getABarrierNode()
  }
}

module BolaFlow = TaintTracking::Global<BolaConfig>;

from DataFlow::Node source, DataFlow::Node sink, Function f
where
  BolaFlow::flow(source, sink) and
  f = sink.getScope()
select sink,
  "Object lookup in '" + f.getName() + "' is keyed by $@ with no dominating ownership check.",
  source, "user-controlled input"
