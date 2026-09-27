from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from .models import BoundaryModel, SourceSpec
from .utils import write_json

# Version of the CodeQL JavaScript library the generated pack is written and tested against.
CODEQL_JAVASCRIPT_ALL_VERSION = "2.7.0"


class TaintModelGenerator:
    """Emits ActionTaint source models and a generated CodeQL query pack."""

    def emit(self, output_dir: Path, boundaries: list[BoundaryModel]) -> tuple[Path, Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        source_specs = [spec for boundary in boundaries for spec in boundary.source_specs]
        pack_path = output_dir / "codeql-pack"
        queries_dir = pack_path / "queries"
        suite_dir = pack_path / "codeql-suites"
        model_path = pack_path / "models" / "actiontaint-sources.json"
        query_path = queries_dir / "ActionTaintGenerated.ql"
        queries_dir.mkdir(parents=True, exist_ok=True)
        suite_dir.mkdir(parents=True, exist_ok=True)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(
            model_path,
            {
                "schema": "actiontaint.boundary.v1",
                "boundaries": [self._boundary_to_dict(boundary) for boundary in boundaries],
            },
        )
        (pack_path / "qlpack.yml").write_text(self._render_qlpack(), encoding="utf-8")
        (suite_dir / "actiontaint.qls").write_text(self._render_query_suite(), encoding="utf-8")
        query_path.write_text(self._render_codeql(source_specs), encoding="utf-8")
        (queries_dir / "ActionTaintGenerated.md").write_text(self._render_query_help(), encoding="utf-8")
        return model_path, query_path, pack_path

    def _boundary_to_dict(self, boundary: BoundaryModel) -> dict:
        data = asdict(boundary)
        return data

    def _render_codeql(self, specs: list[SourceSpec]) -> str:
        return (
            QUERY_HEADER
            + "\n"
            + self._render_source_predicate(specs)
            + "\n\n"
            + self._render_closure_predicate(specs)
            + "\n"
            + QUERY_BODY
        )

    def _render_source_predicate(self, specs: list[SourceSpec]) -> str:
        param_specs = [spec for spec in specs if spec.index is not None]
        if not param_specs:
            return "predicate actionTaintSourceSpec(string file, string fun, int idx, string label) { none() }"
        clauses = []
        for spec in param_specs:
            file_value = self._ql_string(spec.file)
            function_value = self._ql_string(spec.function_name)
            label_value = self._ql_string(spec.parameter)
            clauses.append(
                f"  file = {file_value} and fun = {function_value} and idx = {spec.index} and label = {label_value}"
            )
        return "predicate actionTaintSourceSpec(string file, string fun, int idx, string label) {\n" + "\n  or\n".join(clauses) + "\n}"

    def _render_closure_predicate(self, specs: list[SourceSpec]) -> str:
        closure_specs = [spec for spec in specs if spec.index is None and spec.expression]
        if not closure_specs:
            return "predicate actionTaintClosureSpec(string file, string fun, string name, string label) { none() }"
        clauses = []
        for spec in closure_specs:
            clauses.append(
                f"  file = {self._ql_string(spec.file)} and fun = {self._ql_string(spec.function_name)} and "
                f"name = {self._ql_string(spec.expression or '')} and label = {self._ql_string(spec.parameter)}"
            )
        return (
            "predicate actionTaintClosureSpec(string file, string fun, string name, string label) {\n"
            + "\n  or\n".join(clauses)
            + "\n}"
        )

    def _ql_string(self, value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def _render_qlpack(self) -> str:
        return f"""name: actiontaint/generated-nextjs-actions
version: 0.0.1
library: false
defaultSuiteFile: codeql-suites/actiontaint.qls
dependencies:
  codeql/javascript-all: {CODEQL_JAVASCRIPT_ALL_VERSION}
"""

    def _render_query_suite(self) -> str:
        return """- query: queries/ActionTaintGenerated.ql
"""

    def _render_query_help(self) -> str:
        return """# ActionTaint generated Server Action taint query

This generated query tracks sources discovered by ActionTaint's Next.js Server
Action boundary reconstruction into security-sensitive JavaScript sinks. The
source list is emitted from the framework model rather than guessed directly by
CodeQL.
"""


# Static parts of the generated query. Sinks are matched on method and callee
# names (never on Expr.toString(), which CodeQL abbreviates for long expressions).
QUERY_HEADER = r"""/**
 * @name ActionTaint generated Server Action taint query
 * @description Tracks framework-discovered Next.js Server Action inputs into dangerous sinks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id js/actiontaint/generated-server-action-taint
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-078
 *       external/cwe/cwe-089
 *       external/cwe/cwe-601
 *       external/cwe/cwe-639
 *       external/cwe/cwe-918
 */

import javascript
"""

QUERY_BODY = r"""
/** Holds if `f` is the function the ActionTaint parser recorded as `fun` in `file`. */
predicate actionFunction(Function f, string file, string fun) {
  file = f.getFile().getRelativePath() and
  (
    fun = f.getName()
    or
    fun = "default" and
    not exists(f.getName()) and
    exists(ExportDefaultDeclaration d | d.getOperand() = f)
  )
}

predicate actionTaintSource(DataFlow::Node source, string file, string fun, string label) {
  exists(Function f, Parameter p, int idx |
    actionTaintSourceSpec(file, fun, idx, label) and
    actionFunction(f, file, fun) and
    p = f.getParameter(idx) and
    (
      DataFlow::parameterNode(p) = source
      or
      exists(MethodCallExpr c |
        c.getEnclosingFunction() = f and
        c.getMethodName() = ["get", "getAll"] and
        c.getReceiver().(VarAccess).getName() = p.getName() and
        source = DataFlow::exprNode(c)
      )
      or
      exists(MethodCallExpr c |
        c.getEnclosingFunction() = f and
        c.getMethodName() = "fromEntries" and
        c.getReceiver().(VarAccess).getName() = "Object" and
        DataFlow::parameterNode(p).flowsToExpr(c.getArgument(0)) and
        source = DataFlow::exprNode(c)
      )
    )
  )
  or
  // Client-controlled values (searchParams / params) captured by an inline Server Action.
  exists(Function f, string name, VarAccess va |
    actionTaintClosureSpec(file, fun, name, label) and
    actionFunction(f, file, fun) and
    va.getName() = name and
    va.getEnclosingFunction() = f and
    not va.getVariable().getADeclaration().getEnclosingFunction() = f and
    (
      source = DataFlow::exprNode(va)
      or
      exists(PropAccess pa | pa.getBase() = va and source = DataFlow::exprNode(pa))
    )
  )
}

/** Holds if `root` is a string concatenation (or a variable initialised with one) starting with `prefix`. */
predicate hasConstantPrefix(Expr arg, string prefix) {
  exists(StringOps::ConcatenationRoot root |
    (
      root.asExpr() = arg
      or
      exists(VariableDeclarator d |
        d.getBindingPattern().(VarDecl).getVariable() = arg.(VarAccess).getVariable() and
        d.getInit() = root.asExpr()
      )
    ) and
    prefix = root.getFirstLeaf().getStringValue()
  )
}

predicate sqlQueryArgument(MethodCallExpr c, Expr arg) {
  (
    c.getMethodName() = ["query", "execute", "$queryRawUnsafe", "$executeRawUnsafe"]
    or
    c.getMethodName() = "raw" and c.getReceiver().(VarAccess).getName() = "sql"
  ) and
  arg = c.getArgument(0)
}

predicate objectReaches(ObjectExpr o, Expr e) {
  DataFlow::valueNode(o).(DataFlow::SourceNode).flowsToExpr(e)
}

predicate sqlSink(DataFlow::Node sink) {
  exists(MethodCallExpr c, Expr arg | sqlQueryArgument(c, arg) |
    // Object-form queries such as pg's { text, values }: only the SQL text is a sink.
    if exists(ObjectExpr o | objectReaches(o, arg))
    then
      exists(ObjectExpr o |
        objectReaches(o, arg) and
        sink.asExpr() = o.getPropertyByName(["text", "sql", "query"]).getInit()
      )
    else sink.asExpr() = arg
  )
}

predicate ssrfSink(DataFlow::Node sink) {
  exists(CallExpr c, Expr arg |
    arg = c.getArgument(0) and
    (
      not c instanceof MethodCallExpr and c.getCalleeName() = ["fetch", "axios", "got"]
      or
      c.(MethodCallExpr).getReceiver().(VarAccess).getName() = ["axios", "got"] and
      c.(MethodCallExpr).getMethodName() = ["get", "post", "put", "patch", "delete", "head", "request"]
    ) and
    // A fixed scheme://host/ prefix means the client cannot choose the destination host.
    not exists(string p | hasConstantPrefix(arg, p) and p.regexpMatch("(?i)https?://[^/?#]+[/?#].*")) and
    sink.asExpr() = arg
  )
}

predicate redirectSink(DataFlow::Node sink) {
  exists(CallExpr c, Expr arg |
    arg = c.getArgument(0) and
    (
      not c instanceof MethodCallExpr and c.getCalleeName() = ["redirect", "permanentRedirect"]
      or
      c.(MethodCallExpr).getMethodName() = "redirect" and
      c.(MethodCallExpr).getReceiver().(VarAccess).getName() = "NextResponse"
    ) and
    // A fixed same-origin path prefix such as "/posts/" cannot redirect off-site.
    not exists(string p | hasConstantPrefix(arg, p) and p.regexpMatch("/[^/\\\\].*")) and
    sink.asExpr() = arg
  )
}

predicate pathSink(DataFlow::Node sink) {
  exists(CallExpr c |
    c.getCalleeName() =
      ["readFile", "readFileSync", "writeFile", "writeFileSync", "unlink", "unlinkSync", "createReadStream"] and
    sink.asExpr() = c.getArgument(0)
  )
}

predicate commandSink(DataFlow::Node sink) {
  // child_process and similar APIs as modelled by CodeQL (never RegExp.prototype.exec).
  exists(SystemCommandExecution e | sink = e.getACommandArgument() or sink = e.getArgumentList())
  or
  exists(CallExpr c |
    not c instanceof MethodCallExpr and
    c.getCalleeName() = "execa" and
    sink.asExpr() = c.getArgument([0, 1])
  )
}

bindingset[n]
predicate ownershipName(string n) {
  n.regexpMatch("(?i)(user_?id|owner_?id|author_?id|created_?by|team_?id|org_?id|organization_?id|tenant_?id|workspace_?id|account_?id)")
}

/** Holds if an ownership field appears in `root`, directly or in an object literal that flows into it. */
predicate hasOwnershipConstraint(Expr root) {
  exists(Property p | ownershipName(p.getName()) |
    p.getObjectExpr().getParent*() = root
    or
    exists(ObjectExpr o, Expr e |
      p.getObjectExpr().getParent*() = o and
      objectReaches(o, e) and
      e.getParent*() = root
    )
  )
}

/** ORM-style mutations such as prisma.post.delete({ where }) (not Map/Set/cookies/searchParams). */
predicate ormMutationCall(MethodCallExpr c) {
  c.getMethodName() = ["update", "updateMany", "delete", "deleteMany", "upsert"] and
  c.getReceiver() instanceof PropAccess and
  not c.getReceiver().(PropAccess).getPropertyName() = ["searchParams", "headers", "cookies", "params"] and
  not hasOwnershipConstraint(c.getArgument(0))
}

predicate chainStep(MethodCallExpr inner, MethodCallExpr outer) { outer.getReceiver() = inner }

/** supabase.from("table").delete() / .update(...) / .upsert(...) */
predicate supabaseMutation(MethodCallExpr m) {
  m.getMethodName() = ["update", "delete", "upsert"] and
  m.getReceiver().(MethodCallExpr).getMethodName() = "from"
}

predicate supabaseFilter(MethodCallExpr m, MethodCallExpr f) {
  supabaseMutation(m) and
  chainStep+(m, f) and
  f.getMethodName() = ["eq", "match", "in"]
}

predicate supabaseOwnershipFilter(MethodCallExpr m) {
  exists(MethodCallExpr f | supabaseFilter(m, f) |
    f.getMethodName() = "eq" and ownershipName(f.getArgument(0).getStringValue())
    or
    f.getMethodName() = "match" and hasOwnershipConstraint(f.getArgument(0))
  )
}

predicate idorSink(DataFlow::Node sink) {
  exists(MethodCallExpr c | ormMutationCall(c) and sink.asExpr() = c.getArgument(0))
  or
  exists(MethodCallExpr m, MethodCallExpr f |
    supabaseFilter(m, f) and
    not supabaseOwnershipFilter(m) and
    (
      f.getMethodName() = ["eq", "in"] and sink.asExpr() = f.getArgument(1)
      or
      f.getMethodName() = "match" and sink.asExpr() = f.getArgument(0)
    )
  )
}

predicate actionTaintSink(DataFlow::Node sink, string kind) {
  sqlSink(sink) and kind = "SQL Injection"
  or
  ssrfSink(sink) and kind = "SSRF"
  or
  redirectSink(sink) and kind = "Open Redirect"
  or
  pathSink(sink) and kind = "Path Traversal"
  or
  commandSink(sink) and kind = "Command Injection"
  or
  idorSink(sink) and kind = "Broken Authorization / IDOR"
}

module ActionTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string file, string fun, string label | actionTaintSource(source, file, fun, label))
  }

  predicate isSink(DataFlow::Node sink) { actionTaintSink(sink, _) }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Property prop |
      node1.asExpr() = prop.getInit() and
      node2.asExpr() = prop.getObjectExpr()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(CallExpr c |
      node.asExpr() = c and
      c.getCalleeName()
          .regexpMatch(".*(assertAllowed|assertAllowlisted|allowlist|isAllowedHost|assertInternalUrl|assertRelativePath|trustedServerValue).*")
    )
  }
}

module ActionTaintFlow = TaintTracking::Global<ActionTaintConfig>;

string functionLabel(Function f) {
  result = f.getName()
  or
  not exists(f.getName()) and result = "default"
}

import ActionTaintFlow::PathGraph

from
  ActionTaintFlow::PathNode source, ActionTaintFlow::PathNode sink, string file, string fun,
  string label, string kind, Function sinkFun
where
  ActionTaintFlow::flowPath(source, sink) and
  actionTaintSource(source.getNode(), file, fun, label) and
  actionTaintSink(sink.getNode(), kind) and
  sink.getNode().asExpr().getEnclosingFunction() = sinkFun
select sink.getNode(), source, sink,
  "ActionTaint: " + kind + " from " + file + "::" + fun + "::" + label + " to " +
    sinkFun.getFile().getRelativePath() + "::" + functionLabel(sinkFun) + " dangerous sink. Source is $@.",
  source.getNode(), "client-controlled Server Action input"
"""
