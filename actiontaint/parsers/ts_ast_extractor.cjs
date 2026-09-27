#!/usr/bin/env node
"use strict";

let ts;
try {
  ts = require("typescript");
} catch (error) {
  console.error(
    "TypeScript compiler API is unavailable. Run `npm install` in the ActionTaint workspace or use `--parser regex`."
  );
  process.exit(42);
}

const fs = require("fs");
const path = require("path");

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function scriptKindFor(fileName) {
  if (fileName.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (fileName.endsWith(".ts")) return ts.ScriptKind.TS;
  if (fileName.endsWith(".jsx")) return ts.ScriptKind.JSX;
  return ts.ScriptKind.JS;
}

function relPath(root, fileName) {
  return path.relative(root, fileName).split(path.sep).join("/");
}

function lineOf(sourceFile, pos) {
  return sourceFile.getLineAndCharacterOfPosition(pos).line + 1;
}

function hasModifier(node, kind) {
  return Boolean(node.modifiers && node.modifiers.some(modifier => modifier.kind === kind));
}

function isAsync(node) {
  return hasModifier(node, ts.SyntaxKind.AsyncKeyword);
}

function isExported(node, ownerStatement) {
  return (
    hasModifier(node, ts.SyntaxKind.ExportKeyword) ||
    hasModifier(node, ts.SyntaxKind.DefaultKeyword) ||
    (ownerStatement && hasModifier(ownerStatement, ts.SyntaxKind.ExportKeyword))
  );
}

function textOf(sourceFile, node) {
  return node ? node.getText(sourceFile) : "";
}

function bodyText(sourceText, body) {
  if (!body) return "";
  if (ts.isBlock(body)) {
    return sourceText.slice(body.getStart() + 1, body.getEnd() - 1);
  }
  return textOf(body.getSourceFile(), body);
}

function bodyStartLine(sourceFile, body) {
  if (!body) return lineOf(sourceFile, 0);
  return ts.isBlock(body) ? lineOf(sourceFile, body.getStart() + 1) : lineOf(sourceFile, body.getStart());
}

function isStringDirectiveStatement(statement, directive) {
  return (
    ts.isExpressionStatement(statement) &&
    ts.isStringLiteralLike(statement.expression) &&
    statement.expression.text === directive
  );
}

function hasFileDirective(sourceFile, directive) {
  for (const statement of sourceFile.statements) {
    if (isStringDirectiveStatement(statement, directive)) return true;
    if (ts.isExpressionStatement(statement) && ts.isStringLiteralLike(statement.expression)) continue;
    return false;
  }
  return false;
}

function hasInlineDirective(body, directive) {
  if (!body || !ts.isBlock(body)) return false;
  for (const statement of body.statements) {
    if (isStringDirectiveStatement(statement, directive)) return true;
    if (ts.isExpressionStatement(statement) && ts.isStringLiteralLike(statement.expression)) continue;
    return false;
  }
  return false;
}

function paramFacts(sourceFile, params) {
  return params.map((param, index) => {
    let name = textOf(sourceFile, param.name);
    if (ts.isIdentifier(param.name)) {
      name = param.name.text;
    }
    return {
      name,
      index,
      raw: textOf(sourceFile, param),
      typeHint: param.type ? textOf(sourceFile, param.type) : null
    };
  });
}

function functionFact(root, sourceText, sourceFile, node, ownerStatement, fileUseServer) {
  if (!node.body) return null;
  const name = node.name && ts.isIdentifier(node.name) ? node.name.text : "default";
  const exported = isExported(node, ownerStatement);
  const inlineServer = hasInlineDirective(node.body, "use server");
  const asyncFunction = isAsync(node);
  const serverAction = asyncFunction && (inlineServer || (fileUseServer && exported));
  return {
    name,
    startLine: lineOf(sourceFile, node.getStart(sourceFile)),
    endLine: lineOf(sourceFile, node.getEnd()),
    bodyStartLine: bodyStartLine(sourceFile, node.body),
    params: paramFacts(sourceFile, node.parameters || []),
    exported,
    asyncFunction,
    serverAction,
    directiveKind: inlineServer ? "inline" : serverAction ? "file" : null,
    body: bodyText(sourceText, node.body)
  };
}

function collectImports(sourceFile) {
  const imports = [];
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause) continue;
    const source = statement.moduleSpecifier && ts.isStringLiteralLike(statement.moduleSpecifier)
      ? statement.moduleSpecifier.text
      : "";
    const clause = statement.importClause;
    if (clause.name) {
      imports.push({ local: clause.name.text, imported: "default", source });
    }
    if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
      imports.push({ local: clause.namedBindings.name.text, imported: "*", source });
    }
    if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const element of clause.namedBindings.elements) {
        imports.push({
          local: element.name.text,
          imported: element.propertyName ? element.propertyName.text : element.name.text,
          source
        });
      }
    }
  }
  return imports;
}

function attributeValueText(sourceFile, initializer) {
  if (!initializer) return null;
  if (ts.isStringLiteral(initializer)) return initializer.text;
  if (ts.isJsxExpression(initializer)) {
    return initializer.expression ? textOf(sourceFile, initializer.expression) : "";
  }
  return textOf(sourceFile, initializer);
}

function getJsxAttribute(attrs, name) {
  for (const attr of attrs.properties) {
    if (ts.isJsxAttribute(attr) && attr.name && attr.name.text === name) {
      return attr;
    }
  }
  return null;
}

function jsxTagName(node) {
  return node.tagName.getText(node.getSourceFile());
}

function collectCallsiteFacts(sourceFile) {
  const facts = {
    bindAliases: [],
    hooks: [],
    jsxActions: [],
    hiddenInputs: [],
    directCalls: []
  };

  function visit(node) {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const init = node.initializer;
      if (
        ts.isIdentifier(node.name) &&
        ts.isCallExpression(init) &&
        ts.isPropertyAccessExpression(init.expression) &&
        init.expression.name.text === "bind"
      ) {
        facts.bindAliases.push({
          alias: node.name.text,
          target: textOf(sourceFile, init.expression.expression),
          args: init.arguments.map(arg => textOf(sourceFile, arg)),
          line: lineOf(sourceFile, node.getStart(sourceFile))
        });
      }
      if (
        ts.isCallExpression(init) &&
        ts.isIdentifier(init.expression) &&
        ["useActionState", "useFormState"].includes(init.expression.text) &&
        ts.isArrayBindingPattern(node.name)
      ) {
        const second = node.name.elements[1];
        if (second && ts.isBindingElement(second) && ts.isIdentifier(second.name) && init.arguments[0]) {
          facts.hooks.push({
            alias: second.name.text,
            hook: init.expression.text,
            expr: textOf(sourceFile, init.arguments[0]),
            line: lineOf(sourceFile, node.getStart(sourceFile))
          });
        }
      }
    }

    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      facts.directCalls.push({
        name: node.expression.text,
        line: lineOf(sourceFile, node.expression.getStart(sourceFile))
      });
    }
    // Calls through a namespace import, e.g. Actions.save(...)
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression)
    ) {
      facts.directCalls.push({
        name: `${node.expression.expression.text}.${node.expression.name.text}`,
        line: lineOf(sourceFile, node.expression.getStart(sourceFile))
      });
    }

    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
      const tag = jsxTagName(node);
      const attrs = node.attributes;
      if (tag === "form") {
        const action = getJsxAttribute(attrs, "action");
        const expr = action ? attributeValueText(sourceFile, action.initializer) : null;
        if (expr) {
          facts.jsxActions.push({
            kind: "form_action",
            expr,
            tag,
            prop: "action",
            line: lineOf(sourceFile, node.getStart(sourceFile))
          });
        }
      }
      if (tag === "button" || tag === "input") {
        const action = getJsxAttribute(attrs, "formAction");
        const expr = action ? attributeValueText(sourceFile, action.initializer) : null;
        if (expr) {
          facts.jsxActions.push({
            kind: "button_form_action",
            expr,
            tag,
            prop: "formAction",
            line: lineOf(sourceFile, node.getStart(sourceFile))
          });
        }
      }
      if (/^[A-Z]/.test(tag)) {
        for (const attr of attrs.properties) {
          if (!ts.isJsxAttribute(attr)) continue;
          const prop = attr.name.text;
          if (!/(action|Action|formAction)/.test(prop)) continue;
          const expr = attributeValueText(sourceFile, attr.initializer);
          if (expr) {
            facts.jsxActions.push({
              kind: "component_prop",
              expr,
              tag,
              prop,
              line: lineOf(sourceFile, node.getStart(sourceFile))
            });
          }
        }
      }
      if (tag === "input") {
        const typeAttr = getJsxAttribute(attrs, "type");
        const nameAttr = getJsxAttribute(attrs, "name");
        const valueAttr = getJsxAttribute(attrs, "value");
        const typeValue = typeAttr ? attributeValueText(sourceFile, typeAttr.initializer) : null;
        const nameValue = nameAttr ? attributeValueText(sourceFile, nameAttr.initializer) : null;
        if (typeValue === "hidden" && nameValue) {
          facts.hiddenInputs.push({
            name: nameValue,
            value: valueAttr ? attributeValueText(sourceFile, valueAttr.initializer) : null,
            line: lineOf(sourceFile, node.getStart(sourceFile))
          });
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return facts;
}

// Local names exported through `export { a, b as c }` or `export default a`, mapped to their exported names.
function collectExportSpecifiers(sourceFile) {
  const exportsByLocal = new Map();
  const add = (local, exported) => {
    if (!exportsByLocal.has(local)) exportsByLocal.set(local, []);
    exportsByLocal.get(local).push(exported);
  };
  for (const statement of sourceFile.statements) {
    if (
      ts.isExportDeclaration(statement) &&
      !statement.moduleSpecifier &&
      statement.exportClause &&
      ts.isNamedExports(statement.exportClause)
    ) {
      for (const element of statement.exportClause.elements) {
        const local = element.propertyName ? element.propertyName.text : element.name.text;
        add(local, element.name.text);
      }
    }
    if (ts.isExportAssignment(statement) && !statement.isExportEquals && ts.isIdentifier(statement.expression)) {
      add(statement.expression.text, "default");
    }
  }
  return exportsByLocal;
}

function collectFunctions(root, sourceText, sourceFile, fileUseServer) {
  const functions = [];
  const exportSpecifiers = collectExportSpecifiers(sourceFile);

  function applyExportSpecifiers(fact, isTopLevel) {
    fact.exportNames = [];
    if (!isTopLevel || !exportSpecifiers.has(fact.name)) return;
    fact.exportNames = exportSpecifiers.get(fact.name);
    fact.exported = true;
    const inline = fact.directiveKind === "inline";
    fact.serverAction = fact.asyncFunction && (inline || fileUseServer);
    fact.directiveKind = inline ? "inline" : fact.serverAction ? "file" : null;
  }

  function visit(node) {
    if (ts.isFunctionDeclaration(node)) {
      const fact = functionFact(root, sourceText, sourceFile, node, node, fileUseServer);
      if (fact) {
        applyExportSpecifiers(fact, node.parent === sourceFile);
        functions.push(fact);
      }
    }

    if (ts.isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
        const init = declaration.initializer;
        if (
          (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) &&
          init.body
        ) {
          const fact = functionFact(root, sourceText, sourceFile, init, node, fileUseServer);
          if (fact) {
            fact.name = declaration.name.text;
            fact.startLine = lineOf(sourceFile, node.getStart(sourceFile));
            fact.exported = isExported(node, node);
            fact.serverAction = fact.asyncFunction && (hasInlineDirective(init.body, "use server") || (fileUseServer && fact.exported));
            fact.directiveKind = hasInlineDirective(init.body, "use server") ? "inline" : fact.serverAction ? "file" : null;
            applyExportSpecifiers(fact, node.parent === sourceFile);
            functions.push(fact);
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return functions;
}

(async () => {
  const input = JSON.parse(await readStdin());
  const root = path.resolve(input.root);
  const files = [];
  const warnings = [];

  for (const fileName of input.files) {
    const absolute = path.resolve(fileName);
    let sourceText;
    try {
      sourceText = fs.readFileSync(absolute, "utf8");
    } catch (error) {
      warnings.push(`Could not read ${absolute}: ${error.message}`);
      continue;
    }
    const sourceFile = ts.createSourceFile(
      absolute,
      sourceText,
      ts.ScriptTarget.Latest,
      true,
      scriptKindFor(absolute)
    );
    const fileUseServer = hasFileDirective(sourceFile, "use server");
    files.push({
      path: absolute,
      relPath: relPath(root, absolute),
      fileUseServer,
      fileUseClient: hasFileDirective(sourceFile, "use client"),
      imports: collectImports(sourceFile),
      functions: collectFunctions(root, sourceText, sourceFile, fileUseServer),
      callsites: collectCallsiteFacts(sourceFile)
    });
  }

  process.stdout.write(
    JSON.stringify({
      parser: `typescript-compiler-api ${ts.version}`,
      files,
      warnings
    })
  );
})();
