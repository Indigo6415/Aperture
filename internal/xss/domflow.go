package xss

// domflow.go is the AST-based DOM XSS analysis, ported from the taint model in
// dalfox's src/scanning/ast_dom_analysis (sources, sinks, sanitizers, and the
// function-summary, bind, call/apply and Reflect flows it tracks).
//
// It parses a page's script with goja's parser and abstractly interprets it:
// every value carries a taint bit that marks it as attacker-influenced, and a
// dangerous sink (innerHTML, document.write, eval, ...) reached by a tainted
// value is reported as a flow. Functions are interpreted at their call sites,
// so a taint that crosses a helper, a closure, a method, or a bound alias is
// still seen at the sink. Branches and loops use weak updates, and straight-line
// code uses strong ones, so a value reassigned to something clean before the
// sink is correctly not reported.
//
// This is a bounded static model, not a runtime: it does not evaluate
// arithmetic on unknown values, follow the network, or model the full DOM. A
// script it cannot parse falls back to the regex heuristic in checks.go.

import (
	"maps"
	"strconv"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
)

const (
	// maxDomSteps caps how many expressions one script may evaluate. The analysis
	// is a fixed-point-free walk, so this only guards against pathological input.
	maxDomSteps = 50000
	// maxDomDepth caps nested user-function calls.
	maxDomDepth = 12
)

// domValue is the analyzer's abstract value.
//
//   - tainted: the value itself is attacker-influenced (a source, or derived from one).
//   - origin: the source label that taints it, for the finding's report.
//   - known: the value when it is a constant string, so computed property names
//     such as "inner"+"HTML" resolve to a name the sink table recognizes.
//   - props / anyTainted: object and array members. Known keys live in props;
//     a write under an unknown key sets anyTainted, which taints every read that
//     has no specific entry.
//   - fn / class / sink / bound: callable values, which the call logic dispatches on.
type domValue struct {
	tainted    bool
	origin     string
	known      *string
	props      map[string]*domValue
	anyTainted bool
	fn         *domFunc
	class      *domClass
	sink       string
	bound      *domBound
}

// domFunc is a user function, closure, or arrow function, with the scope it
// closes over.
type domFunc struct {
	params   *ast.ParameterList
	body     []ast.Statement
	exprBody ast.Expression
	scope    *domScope
}

// domClass is a class: instance methods live in proto (copied onto each new
// instance), static methods and fields in the owning value's props, and the
// constructor in ctor.
type domClass struct {
	proto map[string]*domValue
	ctor  *domValue
}

// domBound is the result of Function.prototype.bind: a target callable with a
// fixed this and pre-bound leading arguments.
type domBound struct {
	target *domValue
	this   *domValue
	prefix []*domValue
}

// domScope is one lexical scope. Lookups walk parent links up to the global scope.
type domScope struct {
	vars   map[string]*domValue
	parent *domScope
}

// domFrame collects the return values of one user-function invocation.
type domFrame struct {
	ret *domValue
}

// domFlow is one tainted value reaching one sink.
type domFlow struct {
	sink   string
	origin string
}

// domAnalyzer holds one script's analysis state.
type domAnalyzer struct {
	global    *domScope
	flows     []domFlow
	seen      map[string]bool
	steps     int
	depth     int
	condDepth int
	frames    []*domFrame
	active    map[*domFunc]bool
}

// analyzeDOMScript parses one script and returns every tainted-source-to-sink
// flow the analysis finds. It returns an error only when the script does not
// parse, so the caller can fall back to the regex heuristic.
func analyzeDOMScript(src string) ([]domFlow, error) {
	prog, err := parser.ParseFile(nil, "", src, 0)
	if err != nil {
		return nil, err
	}
	a := &domAnalyzer{
		global: &domScope{vars: map[string]*domValue{}},
		seen:   map[string]bool{},
		active: map[*domFunc]bool{},
	}
	a.hoist(prog.Body, a.global)
	a.runStatements(prog.Body, a.global)
	// Functions that are never called still run in a browser, when an event
	// fires or a page calls them later. Run each top-level function once with no
	// arguments, so a sink that reads a source directly inside it is still found.
	for _, v := range a.global.vars {
		if v.fn != nil {
			a.invoke(v.fn, nil, nil)
		}
	}
	return a.flows, nil
}

// lookup finds a name in scope or its ancestors. It returns nil when the name is
// unbound, which the caller treats as a global.
func (s *domScope) lookup(name string) *domValue {
	for sc := s; sc != nil; sc = sc.parent {
		if v, ok := sc.vars[name]; ok {
			return v
		}
	}
	return nil
}

// owner returns the scope that binds name, or nil when it is unbound.
func (s *domScope) owner(name string) *domScope {
	for sc := s; sc != nil; sc = sc.parent {
		if _, ok := sc.vars[name]; ok {
			return sc
		}
	}
	return nil
}

func newDomScope(parent *domScope) *domScope {
	return &domScope{vars: map[string]*domValue{}, parent: parent}
}

// tick counts one unit of work. It returns false once the budget is spent, and
// every caller then returns an empty value, so the walk stops quickly.
func (a *domAnalyzer) tick() bool {
	a.steps++
	return a.steps <= maxDomSteps
}

// report records one flow, deduplicated by sink and origin. A loop body is
// analyzed twice and a helper can run from several call sites, so the same flow
// is seen more than once.
func (a *domAnalyzer) report(sink, origin string) {
	key := sink + "|" + origin
	if a.seen[key] {
		return
	}
	a.seen[key] = true
	a.flows = append(a.flows, domFlow{sink: sink, origin: origin})
}

// --- Source, sink and sanitizer tables -------------------------------------

// domSourceLeaves are browser values an attacker controls, read as a whole.
var domSourceLeaves = map[string]bool{
	"document.URL":         true,
	"document.documentURI": true,
	"document.baseURI":     true,
	"document.referrer":    true,
	"document.cookie":      true,
	"name":                 true,
}

// domSourceContainers are objects whose every property is attacker-influenced
// once read: the URL, and the storage areas a page fills from it.
var domSourceContainers = []string{"location", "document.location", "localStorage", "sessionStorage"}

// domSinkFunctions are callables that render or run their argument, keyed by
// normalized path. The value is the sink name used in findings.
var domSinkFunctions = map[string]string{
	"document.write":       "document.write",
	"document.writeln":     "document.writeln",
	"eval":                 "eval",
	"Function":             "Function",
	"setTimeout":           "setTimeout",
	"setInterval":          "setInterval",
	"location.assign":      "location.assign",
	"location.replace":     "location.replace",
	"document.execCommand": "execCommand",
}

// domSinkMethods are DOM methods that are dangerous whatever object they are
// called on, so they are matched by name rather than by full path.
var domSinkMethods = map[string]bool{
	"insertAdjacentHTML":       true,
	"setAttribute":             true,
	"execCommand":              true,
	"createContextualFragment": true,
}

// domSinkProperties are DOM properties whose assignment renders or navigates to
// the value. Event-handler properties (on...) are matched separately.
var domSinkProperties = map[string]bool{
	"innerHTML":  true,
	"outerHTML":  true,
	"srcdoc":     true,
	"src":        true,
	"href":       true,
	"action":     true,
	"formaction": true,
}

// domSanitizerNames return a value the browser will not interpret as markup or
// code, so their result is untainted. A user-defined function with one of these
// names is a sanitizer too, because the corpus, and real pages, define their own
// encoders.
var domSanitizerNames = map[string]bool{
	"encodeURIComponent": true,
	"encodeURI":          true,
	"escape":             true,
	"encodeHTML":         true,
	"encodeHtml":         true,
	"sanitize":           true,
	"sanitizeHtml":       true,
	"sanitizeHTML":       true,
	"parseInt":           true,
	"parseFloat":         true,
	"Number":             true,
	"Boolean":            true,
}

// normalizeDomPath strips the global-object prefixes so window.location and
// location name the same source, and window.eval and eval the same sink.
func normalizeDomPath(p string) string {
	for _, pre := range []string{"window.", "self.", "globalThis."} {
		if rest, ok := strings.CutPrefix(p, pre); ok {
			return rest
		}
	}
	return p
}

// sourceContainerOf returns the source container that path p reads through, if any.
func sourceContainerOf(p string) (string, bool) {
	for _, c := range domSourceContainers {
		if p == c || strings.HasPrefix(p, c+".") {
			return c, true
		}
	}
	return "", false
}

// isSanitizerPath reports whether a normalized call path names a sanitizer.
// DOMPurify.sanitize and similar are matched by their final segment.
func isSanitizerPath(p string) bool {
	if domSanitizerNames[p] {
		return true
	}
	last := p
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		last = p[i+1:]
	}
	return last == "sanitize"
}

// dangerousAttribute reports whether setting attribute name to a value can
// execute it: any event handler, or a URL attribute that a javascript: value
// would run from.
func dangerousAttribute(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "on") {
		return true
	}
	switch lower {
	case "href", "src", "srcdoc", "action", "formaction", "xlink:href":
		return true
	}
	return false
}

// --- Taint helpers ----------------------------------------------------------

// taintOf reports whether v is attacker-influenced in any part it exposes: the
// value itself, an unknown member, or a known member.
func taintOf(v *domValue) bool {
	if v == nil {
		return false
	}
	if v.tainted || v.anyTainted {
		return true
	}
	for _, p := range v.props {
		if p.tainted {
			return true
		}
	}
	return false
}

// originOf returns the source label carried by a tainted value.
func originOf(v *domValue) string {
	if v == nil {
		return ""
	}
	if v.origin != "" {
		return v.origin
	}
	for _, p := range v.props {
		if p.origin != "" {
			return p.origin
		}
	}
	return ""
}

// merge joins two values from alternative paths: tainted if either is, with
// the known constant kept only when both agree. Object members are merged by key.
func merge(a, b *domValue) *domValue {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := &domValue{
		tainted:    a.tainted || b.tainted,
		anyTainted: a.anyTainted || b.anyTainted,
		fn:         a.fn,
		class:      a.class,
		sink:       a.sink,
		bound:      a.bound,
	}
	if out.fn == nil {
		out.fn, out.class, out.sink, out.bound = b.fn, b.class, b.sink, b.bound
	}
	out.origin = a.origin
	if out.origin == "" {
		out.origin = b.origin
	}
	if a.known != nil && b.known != nil && *a.known == *b.known {
		out.known = a.known
	}
	if len(a.props) > 0 || len(b.props) > 0 {
		out.props = map[string]*domValue{}
		maps.Copy(out.props, a.props)
		for k, v := range b.props {
			if old, ok := out.props[k]; ok {
				out.props[k] = merge(old, v)
			} else {
				out.props[k] = v
			}
		}
	}
	return out
}

// anyArgTainted reports whether any argument is attacker-influenced, along with
// the first origin found. A call with no sink or source model uses this to
// decide whether its result is tainted.
func anyArgTainted(args []*domValue) (bool, string) {
	for _, arg := range args {
		if taintOf(arg) {
			return true, originOf(arg)
		}
	}
	return false, ""
}

// --- Hoisting and statements -----------------------------------------------

// hoist defines a block's function and class declarations before any statement
// runs, so a function called above its own declaration still resolves.
func (a *domAnalyzer) hoist(stmts []ast.Statement, scope *domScope) {
	for _, s := range stmts {
		switch st := s.(type) {
		case *ast.FunctionDeclaration:
			scope.vars[string(st.Function.Name.Name)] = &domValue{fn: a.funcOf(st.Function.ParameterList, st.Function.Body.List, nil, scope)}
		case *ast.ClassDeclaration:
			scope.vars[string(st.Class.Name.Name)] = a.classOf(st.Class, scope)
		}
	}
}

// funcOf builds a callable value that closes over scope.
func (a *domAnalyzer) funcOf(params *ast.ParameterList, body []ast.Statement, exprBody ast.Expression, scope *domScope) *domFunc {
	return &domFunc{params: params, body: body, exprBody: exprBody, scope: scope}
}

// classOf builds a class value: its methods, its statics, and its constructor.
func (a *domAnalyzer) classOf(c *ast.ClassLiteral, scope *domScope) *domValue {
	cls := &domClass{proto: map[string]*domValue{}}
	statics := map[string]*domValue{}
	for _, el := range c.Body {
		m, ok := el.(*ast.MethodDefinition)
		if !ok || m.Body == nil {
			continue
		}
		name := a.keyNameOf(m.Key, m.Computed, scope)
		fv := &domValue{fn: a.funcOf(m.Body.ParameterList, m.Body.Body.List, nil, scope)}
		switch {
		case name == "constructor":
			cls.ctor = fv
		case m.Static:
			statics[name] = fv
		default:
			cls.proto[name] = fv
		}
	}
	return &domValue{class: cls, props: statics}
}

// runStatements executes a statement list in order.
func (a *domAnalyzer) runStatements(stmts []ast.Statement, scope *domScope) {
	for _, s := range stmts {
		a.execStmt(s, scope)
	}
}

// weak runs body with weak updates: a value assigned inside it may or may not
// have run, so the old value is kept and merged in. It is used for branches,
// loops, and catch blocks.
func (a *domAnalyzer) weak(body func()) {
	a.condDepth++
	defer func() { a.condDepth-- }()
	body()
}

// execStmt interprets one statement.
func (a *domAnalyzer) execStmt(s ast.Statement, scope *domScope) {
	if s == nil || !a.tick() {
		return
	}
	switch st := s.(type) {
	case *ast.ExpressionStatement:
		a.eval(st.Expression, scope)
	case *ast.VariableStatement:
		a.declare(st.List, scope)
	case *ast.LexicalDeclaration:
		a.declare(st.List, scope)
	case *ast.ReturnStatement:
		v := a.eval(st.Argument, scope)
		if n := len(a.frames); n > 0 {
			a.frames[n-1].ret = merge(a.frames[n-1].ret, v)
		}
	case *ast.BlockStatement:
		child := newDomScope(scope)
		a.hoist(st.List, child)
		a.runStatements(st.List, child)
	case *ast.IfStatement:
		a.eval(st.Test, scope)
		// Either branch may run, so assignments inside them are weak.
		a.weak(func() {
			a.execStmt(st.Consequent, scope)
			if st.Alternate != nil {
				a.execStmt(st.Alternate, scope)
			}
		})
	case *ast.ForStatement:
		child := newDomScope(scope)
		a.forInit(st.Initializer, child)
		// The body runs zero or more times, so it is weak. Two passes let a value
		// assigned late in the body reach a read at the top of the body.
		a.weak(func() {
			for range 2 {
				a.eval(st.Test, child)
				a.execStmt(st.Body, child)
				a.eval(st.Update, child)
			}
		})
	case *ast.ForInStatement:
		a.execForEach(st.Into, st.Source, st.Body, scope, false)
	case *ast.ForOfStatement:
		a.execForEach(st.Into, st.Source, st.Body, scope, true)
	case *ast.WhileStatement:
		a.weak(func() {
			for range 2 {
				a.eval(st.Test, scope)
				a.execStmt(st.Body, scope)
			}
		})
	case *ast.DoWhileStatement:
		a.weak(func() {
			for range 2 {
				a.execStmt(st.Body, scope)
				a.eval(st.Test, scope)
			}
		})
	case *ast.SwitchStatement:
		a.eval(st.Discriminant, scope)
		child := newDomScope(scope)
		for _, c := range st.Body {
			a.hoist(c.Consequent, child)
		}
		a.weak(func() {
			for _, c := range st.Body {
				a.eval(c.Test, child)
				a.runStatements(c.Consequent, child)
			}
		})
	case *ast.TryStatement:
		a.execStmt(st.Body, scope)
		if st.Catch != nil {
			// The catch block runs only if the try block threw, so it is weak.
			a.weak(func() {
				child := newDomScope(scope)
				a.bindTarget(st.Catch.Parameter, &domValue{}, child, true)
				a.execStmt(st.Catch.Body, child)
			})
		}
		if st.Finally != nil {
			a.execStmt(st.Finally, scope)
		}
	case *ast.ThrowStatement:
		a.eval(st.Argument, scope)
	case *ast.LabelledStatement:
		a.execStmt(st.Statement, scope)
	case *ast.WithStatement:
		a.eval(st.Object, scope)
		a.execStmt(st.Body, scope)
	case *ast.ClassDeclaration:
		scope.vars[string(st.Class.Name.Name)] = a.classOf(st.Class, scope)
	}
}

// forInit runs a for loop's initializer.
func (a *domAnalyzer) forInit(init ast.ForLoopInitializer, scope *domScope) {
	switch in := init.(type) {
	case *ast.ForLoopInitializerExpression:
		a.eval(in.Expression, scope)
	case *ast.ForLoopInitializerVarDeclList:
		a.declare(in.List, scope)
	case *ast.ForLoopInitializerLexicalDecl:
		a.declare(in.LexicalDeclaration.List, scope)
	}
}

// execForEach runs for-in and for-of. The loop variable of a for-of over
// tainted data is tainted; a for-in key is a property name, so it is clean.
func (a *domAnalyzer) execForEach(into ast.ForInto, source ast.Expression, body ast.Statement, scope *domScope, ofLoop bool) {
	src := a.eval(source, scope)
	elem := &domValue{}
	if ofLoop && taintOf(src) {
		elem = &domValue{tainted: true, origin: originOf(src)}
	}
	child := newDomScope(scope)
	a.weak(func() {
		for range 2 {
			iter := newDomScope(child)
			switch in := into.(type) {
			case *ast.ForIntoVar:
				a.bindTarget(in.Binding.Target, elem, iter, true)
			case *ast.ForDeclaration:
				a.bindTarget(in.Target, elem, iter, true)
			case *ast.ForIntoExpression:
				a.bindTarget(in.Expression, elem, iter, false)
			}
			a.execStmt(body, iter)
		}
	})
}

// declare handles a var, let or const statement.
func (a *domAnalyzer) declare(list []*ast.Binding, scope *domScope) {
	for _, b := range list {
		v := &domValue{}
		if b.Initializer != nil {
			v = a.eval(b.Initializer, scope)
		}
		a.bindTarget(b.Target, v, scope, true)
	}
}

// bindTarget binds v to a binding target. A declaration creates the name in
// scope; an assignment updates the existing one. A destructuring pattern
// binds each part to the matching member of v.
func (a *domAnalyzer) bindTarget(target ast.Expression, v *domValue, scope *domScope, declare bool) {
	switch t := target.(type) {
	case *ast.Identifier:
		name := string(t.Name)
		if declare {
			scope.vars[name] = v
		} else {
			a.setVar(scope, name, v)
		}
	case *ast.ObjectPattern:
		for _, p := range t.Properties {
			switch pk := p.(type) {
			case *ast.PropertyKeyed:
				key := a.keyNameOf(pk.Key, pk.Computed, scope)
				a.bindTarget(pk.Value, readMember(v, key), scope, declare)
			case *ast.PropertyShort:
				a.bindTarget(&pk.Name, readMember(v, string(pk.Name.Name)), scope, declare)
			}
		}
		if t.Rest != nil {
			a.bindTarget(t.Rest, v, scope, declare)
		}
	case *ast.ArrayPattern:
		for i, el := range t.Elements {
			if el != nil {
				a.bindTarget(el, readMember(v, strconv.Itoa(i)), scope, declare)
			}
		}
		if t.Rest != nil {
			a.bindTarget(t.Rest, v, scope, declare)
		}
	case *ast.AssignExpression:
		// A default value in a pattern, as in {x = 1}: the binding takes either.
		a.bindTarget(t.Left, merge(v, a.eval(t.Right, scope)), scope, declare)
	}
}

// setVar assigns to an existing binding, or creates a global when the name is
// unbound. Inside a conditional the old value is kept and merged in.
func (a *domAnalyzer) setVar(scope *domScope, name string, v *domValue) {
	owner := scope.owner(name)
	if owner == nil {
		owner = a.global
	}
	if a.condDepth > 0 {
		v = merge(owner.vars[name], v)
	}
	owner.vars[name] = v
}

// --- Expressions ------------------------------------------------------------

// eval interprets one expression and returns its abstract value.
func (a *domAnalyzer) eval(e ast.Expression, scope *domScope) *domValue {
	if e == nil || !a.tick() {
		return &domValue{}
	}
	switch x := e.(type) {
	case *ast.StringLiteral:
		s := string(x.Value)
		return &domValue{known: &s}
	case *ast.Identifier:
		return a.evalIdentifier(string(x.Name), scope)
	case *ast.TemplateLiteral:
		return a.evalTemplate(x, scope)
	case *ast.ArrayLiteral:
		return a.evalArray(x, scope)
	case *ast.ObjectLiteral:
		return a.evalObject(x, scope)
	case *ast.FunctionLiteral:
		return &domValue{fn: a.funcOf(x.ParameterList, x.Body.List, nil, scope)}
	case *ast.ArrowFunctionLiteral:
		return a.evalArrow(x, scope)
	case *ast.ClassLiteral:
		return a.classOf(x, scope)
	case *ast.ConditionalExpression:
		a.eval(x.Test, scope)
		return merge(a.eval(x.Consequent, scope), a.eval(x.Alternate, scope))
	case *ast.BinaryExpression:
		return a.evalBinary(x, scope)
	case *ast.SequenceExpression:
		var last *domValue
		for _, sub := range x.Sequence {
			last = a.eval(sub, scope)
		}
		if last == nil {
			return &domValue{}
		}
		return last
	case *ast.AssignExpression:
		return a.assign(x, scope)
	case *ast.DotExpression:
		return a.readDot(x, scope)
	case *ast.PrivateDotExpression:
		return a.eval(x.Left, scope)
	case *ast.BracketExpression:
		return a.readBracket(x, scope)
	case *ast.OptionalChain:
		return a.eval(x.Expression, scope)
	case *ast.Optional:
		return a.eval(x.Expression, scope)
	case *ast.CallExpression:
		return a.evalCall(x, scope)
	case *ast.NewExpression:
		return a.evalNew(x, scope)
	case *ast.ThisExpression:
		if v := scope.lookup("this"); v != nil {
			return v
		}
		return &domValue{}
	case *ast.SpreadElement:
		return a.eval(x.Expression, scope)
	}
	// Unary operators (typeof, !, -, ++, ...) produce numbers, booleans or
	// strings, which cannot carry markup, so they are untainted.
	return &domValue{}
}

// evalIdentifier resolves a name. An unbound name is a browser global: location
// is a source, and eval or Function are sinks.
func (a *domAnalyzer) evalIdentifier(name string, scope *domScope) *domValue {
	if v := scope.lookup(name); v != nil {
		return v
	}
	// A bare source container (location, localStorage, sessionStorage) is itself
	// attacker-influenced, so every member read from it is too.
	if _, ok := sourceContainerOf(name); ok {
		return &domValue{tainted: true, origin: name}
	}
	if sink, ok := domSinkFunctions[name]; ok {
		return &domValue{sink: sink}
	}
	return &domValue{}
}

// evalTemplate joins a template literal. It is constant only if every part is.
func (a *domAnalyzer) evalTemplate(t *ast.TemplateLiteral, scope *domScope) *domValue {
	var sb strings.Builder
	known := true
	out := &domValue{}
	for i, el := range t.Elements {
		sb.WriteString(string(el.Parsed))
		if i < len(t.Expressions) {
			v := a.eval(t.Expressions[i], scope)
			out = merge(out, &domValue{tainted: taintOf(v), origin: originOf(v)})
			if v.known != nil {
				sb.WriteString(*v.known)
			} else {
				known = false
			}
		}
	}
	if known {
		s := sb.String()
		out.known = &s
	}
	return out
}

// evalArray builds an array with one prop per index, so a later indexed read
// or a call through apply can take the exact element. A spread element marks
// the whole array as unknown.
func (a *domAnalyzer) evalArray(x *ast.ArrayLiteral, scope *domScope) *domValue {
	out := &domValue{props: map[string]*domValue{}}
	for i, el := range x.Value {
		if el == nil {
			continue
		}
		if sp, ok := el.(*ast.SpreadElement); ok {
			v := a.eval(sp.Expression, scope)
			out.anyTainted = out.anyTainted || taintOf(v)
			out.origin = firstNonEmpty(out.origin, originOf(v))
			continue
		}
		out.props[strconv.Itoa(i)] = a.eval(el, scope)
	}
	return out
}

// evalObject builds an object literal. A method or getter becomes a callable
// member; a computed key that cannot be resolved taints the whole object if the
// value is tainted.
func (a *domAnalyzer) evalObject(x *ast.ObjectLiteral, scope *domScope) *domValue {
	out := &domValue{props: map[string]*domValue{}}
	for _, p := range x.Value {
		switch pk := p.(type) {
		case *ast.PropertyKeyed:
			key := a.keyNameOf(pk.Key, pk.Computed, scope)
			var v *domValue
			if fl, ok := pk.Value.(*ast.FunctionLiteral); ok {
				v = &domValue{fn: a.funcOf(fl.ParameterList, fl.Body.List, nil, scope)}
			} else {
				v = a.eval(pk.Value, scope)
			}
			if key == "" {
				out.anyTainted = out.anyTainted || taintOf(v)
				out.origin = firstNonEmpty(out.origin, originOf(v))
			} else {
				out.props[key] = v
			}
		case *ast.PropertyShort:
			out.props[string(pk.Name.Name)] = a.evalIdentifier(string(pk.Name.Name), scope)
		case *ast.SpreadElement:
			src := a.eval(pk.Expression, scope)
			maps.Copy(out.props, src.props)
			out.anyTainted = out.anyTainted || src.anyTainted || src.tainted
			out.origin = firstNonEmpty(out.origin, originOf(src))
		}
	}
	return out
}

// evalArrow builds an arrow function, with an expression body or a block body.
func (a *domAnalyzer) evalArrow(x *ast.ArrowFunctionLiteral, scope *domScope) *domValue {
	switch body := x.Body.(type) {
	case *ast.ExpressionBody:
		return &domValue{fn: a.funcOf(x.ParameterList, nil, body.Expression, scope)}
	case *ast.BlockStatement:
		return &domValue{fn: a.funcOf(x.ParameterList, body.List, nil, scope)}
	}
	return &domValue{fn: a.funcOf(x.ParameterList, nil, nil, scope)}
}

// evalBinary joins two operands. Concatenation of two constants stays constant,
// which is what lets "inner"+"HTML" resolve to a sink name. Comparisons yield a
// boolean and are untainted.
func (a *domAnalyzer) evalBinary(x *ast.BinaryExpression, scope *domScope) *domValue {
	l := a.eval(x.Left, scope)
	r := a.eval(x.Right, scope)
	if x.Comparison {
		return &domValue{}
	}
	out := merge(&domValue{tainted: taintOf(l), origin: originOf(l)}, &domValue{tainted: taintOf(r), origin: originOf(r)})
	if x.Operator == token.PLUS && l.known != nil && r.known != nil {
		s := *l.known + *r.known
		out.known = &s
	}
	return out
}

// readDot reads obj.name. A path that names a sink or a source is resolved
// first; otherwise the member comes from the object, or the object's taint.
func (a *domAnalyzer) readDot(x *ast.DotExpression, scope *domScope) *domValue {
	name := string(x.Identifier.Name)
	if p, ok := a.pathOf(x, scope); ok {
		norm := normalizeDomPath(p)
		if sink, ok := domSinkFunctions[norm]; ok {
			return &domValue{sink: sink}
		}
		if domSourceLeaves[norm] {
			return &domValue{tainted: true, origin: norm}
		}
		if _, ok := sourceContainerOf(norm); ok {
			return &domValue{tainted: true, origin: norm}
		}
	}
	base := a.eval(x.Left, scope)
	if domSinkMethods[name] {
		return &domValue{sink: name}
	}
	return readMember(base, name)
}

// readBracket reads obj[key]. A constant key behaves like a dot read. An unknown
// key returns the taint of every member, since any of them might be read.
func (a *domAnalyzer) readBracket(x *ast.BracketExpression, scope *domScope) *domValue {
	if p, ok := a.pathOf(x, scope); ok {
		norm := normalizeDomPath(p)
		if sink, ok := domSinkFunctions[norm]; ok {
			return &domValue{sink: sink}
		}
		if domSourceLeaves[norm] {
			return &domValue{tainted: true, origin: norm}
		}
		if _, ok := sourceContainerOf(norm); ok {
			return &domValue{tainted: true, origin: norm}
		}
	}
	base := a.eval(x.Left, scope)
	key := a.eval(x.Member, scope)
	if key.known != nil {
		if domSinkMethods[*key.known] {
			return &domValue{sink: *key.known}
		}
		return readMember(base, *key.known)
	}
	return &domValue{tainted: taintOf(base) || taintOf(key), origin: firstNonEmpty(originOf(base), originOf(key))}
}

// readMember reads a known member of v. A member that is not stored on v falls
// back to v's own taint, because a tainted string's methods and fields are tainted.
func readMember(v *domValue, name string) *domValue {
	if v == nil {
		return &domValue{}
	}
	if p, ok := v.props[name]; ok {
		return p
	}
	return &domValue{tainted: v.tainted || v.anyTainted, origin: originOf(v)}
}

// keyNameOf returns the property name of an object-literal or class key, or ""
// when a computed key cannot be resolved to a constant.
func (a *domAnalyzer) keyNameOf(key ast.Expression, computed bool, scope *domScope) string {
	if !computed {
		switch k := key.(type) {
		case *ast.Identifier:
			return string(k.Name)
		case *ast.StringLiteral:
			return string(k.Value)
		case *ast.NumberLiteral:
			return k.Literal
		}
	}
	if v := a.eval(key, scope); v.known != nil {
		return *v.known
	}
	return ""
}

// pathOf renders a member chain such as window["doc"+"ument"].write as a dotted
// path, resolving constant computed keys. It fails for anything else, like a call
// result, so a sink can only be named by a path that is actually written out.
func (a *domAnalyzer) pathOf(e ast.Expression, scope *domScope) (string, bool) {
	switch x := e.(type) {
	case *ast.Identifier:
		return string(x.Name), true
	case *ast.DotExpression:
		left, ok := a.pathOf(x.Left, scope)
		if !ok {
			return "", false
		}
		return left + "." + string(x.Identifier.Name), true
	case *ast.BracketExpression:
		left, ok := a.pathOf(x.Left, scope)
		if !ok {
			return "", false
		}
		key := a.eval(x.Member, scope)
		if key.known == nil {
			return "", false
		}
		return left + "." + *key.known, true
	case *ast.OptionalChain:
		return a.pathOf(x.Expression, scope)
	case *ast.Optional:
		return a.pathOf(x.Expression, scope)
	}
	return "", false
}

// firstNonEmpty returns the first argument that is not empty.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- Assignment --------------------------------------------------------------

// assign interprets an assignment and returns the assigned value. A plain
// assignment replaces the target; a compound one (+=, ...) joins the old value.
// Assigning a tainted value to a sink property or to location is reported.
func (a *domAnalyzer) assign(x *ast.AssignExpression, scope *domScope) *domValue {
	rhs := a.eval(x.Right, scope)
	if x.Operator != token.ASSIGN {
		rhs = merge(a.eval(x.Left, scope), rhs)
	}
	switch l := x.Left.(type) {
	case *ast.Identifier:
		name := string(l.Name)
		if name == "location" && scope.lookup(name) == nil && taintOf(rhs) {
			a.report("location", originOf(rhs))
		}
		a.setVar(scope, name, rhs)
	case *ast.DotExpression:
		a.assignMember(a.eval(l.Left, scope), string(l.Identifier.Name), rhs, l, scope)
	case *ast.BracketExpression:
		container := a.eval(l.Left, scope)
		key := a.eval(l.Member, scope)
		if key.known != nil {
			a.assignMember(container, *key.known, rhs, l, scope)
		} else {
			// The property is unknown, so the write may land on any member.
			container.anyTainted = container.anyTainted || taintOf(rhs)
		}
	case *ast.ObjectPattern, *ast.ArrayPattern:
		a.bindTarget(l, rhs, scope, false)
	}
	return rhs
}

// assignMember writes container[name] = v, and reports a sink when name is a
// dangerous property. An assignment to location.href navigates, so it is a
// location sink.
func (a *domAnalyzer) assignMember(container *domValue, name string, v *domValue, target ast.Expression, scope *domScope) {
	if p, ok := a.pathOf(target, scope); ok {
		norm := normalizeDomPath(p)
		if norm == "location.href" && taintOf(v) {
			a.report("location", originOf(v))
		}
	}
	dangerousProp := domSinkProperties[name] || strings.HasPrefix(strings.ToLower(name), "on")
	if dangerousProp && taintOf(v) {
		a.report(name, originOf(v))
	}
	// Assigning a function to onmessage registers a message handler, so it is
	// invoked with the attacker-controlled event.
	if strings.EqualFold(name, "onmessage") && v.fn != nil {
		a.invoke(v.fn, container, []*domValue{messageEvent()})
	}
	if container == nil {
		return
	}
	if container.props == nil {
		container.props = map[string]*domValue{}
	}
	if old, ok := container.props[name]; ok && a.condDepth > 0 {
		v = merge(old, v)
	}
	container.props[name] = v
}

// messageEvent is the event object a message listener receives. Its data is
// attacker-controlled, so every member of it is tainted.
func messageEvent() *domValue {
	return &domValue{tainted: true, origin: "postMessage data"}
}

// --- Calls -------------------------------------------------------------------

// evalCall interprets a call. Named sinks and sanitizers come first, then
// Reflect, then method dispatch, and finally any callable value.
func (a *domAnalyzer) evalCall(x *ast.CallExpression, scope *domScope) *domValue {
	args := a.evalArgs(x.ArgumentList, scope)
	callee := unwrapOptional(x.Callee)

	if p, ok := a.pathOf(callee, scope); ok {
		norm := normalizeDomPath(p)
		if sink, ok := domSinkFunctions[norm]; ok {
			return a.sinkCall(sink, args)
		}
		if isSanitizerPath(norm) {
			return &domValue{}
		}
		switch norm {
		case "Reflect.apply":
			return a.callValue(argAt(args, 0), argAt(args, 1), listArgs(argAt(args, 2)))
		case "Reflect.construct":
			return a.constructValue(argAt(args, 0), listArgs(argAt(args, 1)))
		}
	}

	if dot, ok := callee.(*ast.DotExpression); ok {
		return a.callMethod(a.eval(dot.Left, scope), string(dot.Identifier.Name), args)
	}
	if br, ok := callee.(*ast.BracketExpression); ok {
		recv := a.eval(br.Left, scope)
		if key := a.eval(br.Member, scope); key.known != nil {
			return a.callMethod(recv, *key.known, args)
		}
	}
	return a.callValue(a.eval(callee, scope), nil, args)
}

// callMethod dispatches recv.name(args): the call, apply and bind methods of a
// callable, a dangerous DOM method, a stored member, array mutators, the
// message listener, and then the generic rule that a call on tainted data is tainted.
func (a *domAnalyzer) callMethod(recv *domValue, name string, args []*domValue) *domValue {
	if isCallable(recv) {
		switch name {
		case "call":
			return a.callValue(recv, argAt(args, 0), argsFrom(args, 1))
		case "apply":
			return a.callValue(recv, argAt(args, 0), listArgs(argAt(args, 1)))
		case "bind":
			return &domValue{bound: &domBound{target: recv, this: argAt(args, 0), prefix: argsFrom(args, 1)}}
		}
	}
	if domSinkMethods[name] {
		return a.sinkCall(name, args)
	}
	if fv, ok := recv.props[name]; ok {
		return a.callValue(fv, recv, args)
	}
	switch name {
	case "push", "unshift":
		recv.anyTainted = recv.anyTainted || anyTaintedArgs(args)
		return &domValue{}
	case "splice":
		recv.anyTainted = recv.anyTainted || anyTaintedArgs(argsFrom(args, 2))
		return &domValue{}
	case "addEventListener":
		if ev := argAt(args, 0); ev.known != nil && *ev.known == "message" {
			if h := argAt(args, 1); h.fn != nil {
				a.invoke(h.fn, nil, []*domValue{messageEvent()})
			}
		}
		return &domValue{}
	}
	tainted, origin := anyArgTainted(args)
	return &domValue{
		tainted: taintOf(recv) || tainted,
		origin:  firstNonEmpty(originOf(recv), origin),
	}
}

// evalNew interprets new X(args). new Function(...) is a sink.
func (a *domAnalyzer) evalNew(x *ast.NewExpression, scope *domScope) *domValue {
	args := a.evalArgs(x.ArgumentList, scope)
	callee := a.eval(x.Callee, scope)
	return a.constructValue(callee, args)
}

// evalArgs evaluates call arguments. A spread argument is one value carrying the
// taint of everything it expands to.
func (a *domAnalyzer) evalArgs(list []ast.Expression, scope *domScope) []*domValue {
	out := make([]*domValue, 0, len(list))
	for _, arg := range list {
		if sp, ok := arg.(*ast.SpreadElement); ok {
			v := a.eval(sp.Expression, scope)
			out = append(out, &domValue{tainted: taintOf(v), origin: originOf(v)})
			continue
		}
		out = append(out, a.eval(arg, scope))
	}
	return out
}

// callValue calls a callable value with an explicit this and arguments.
func (a *domAnalyzer) callValue(fv *domValue, this *domValue, args []*domValue) *domValue {
	if fv == nil {
		return &domValue{}
	}
	switch {
	case fv.sink != "":
		return a.sinkCall(fv.sink, args)
	case fv.bound != nil:
		all := append(append([]*domValue{}, fv.bound.prefix...), args...)
		return a.callValue(fv.bound.target, fv.bound.this, all)
	case fv.fn != nil:
		return a.invoke(fv.fn, this, args)
	case fv.class != nil:
		return a.constructValue(fv, args)
	}
	// An unknown callee: its result is tainted if the callee itself is (a source
	// member such as localStorage.getItem returns tainted data) or anything it
	// was given is.
	tainted, origin := anyArgTainted(args)
	return &domValue{tainted: tainted || taintOf(fv), origin: firstNonEmpty(origin, originOf(fv))}
}

// constructValue calls a constructor. Function is a sink; a class or function
// yields a new object carrying the class's methods; anything else is treated
// like a generic call.
func (a *domAnalyzer) constructValue(fv *domValue, args []*domValue) *domValue {
	if fv == nil {
		return &domValue{}
	}
	if fv.sink == "Function" {
		return a.sinkCall("Function", args)
	}
	if fv.class != nil {
		obj := &domValue{props: map[string]*domValue{}}
		maps.Copy(obj.props, fv.class.proto)
		if ctor := fv.class.ctor; ctor != nil && ctor.fn != nil {
			a.invoke(ctor.fn, obj, args)
		}
		return obj
	}
	if fv.fn != nil {
		obj := &domValue{props: map[string]*domValue{}}
		a.invoke(fv.fn, obj, args)
		return obj
	}
	tainted, origin := anyArgTainted(args)
	return &domValue{tainted: tainted, origin: origin}
}

// sinkCall checks one dangerous call. Each sink names which argument is the
// dangerous one: the markup or code, the attribute value, or the command value.
func (a *domAnalyzer) sinkCall(sink string, args []*domValue) *domValue {
	var dangerous []*domValue
	switch sink {
	case "Function":
		dangerous = args
	case "insertAdjacentHTML":
		dangerous = []*domValue{argAt(args, 1)}
	case "setAttribute":
		// The attribute name decides whether the value can run. An unknown name
		// is not reported, so a benign attribute is not flagged on a guess.
		if name := argAt(args, 0); name.known != nil && dangerousAttribute(*name.known) {
			dangerous = []*domValue{argAt(args, 1)}
		}
	case "execCommand":
		if cmd := argAt(args, 0); cmd.known != nil && strings.EqualFold(*cmd.known, "inserthtml") {
			dangerous = []*domValue{argAt(args, 2)}
		}
	default:
		dangerous = []*domValue{argAt(args, 0)}
	}
	for _, v := range dangerous {
		if taintOf(v) {
			a.report(sink, originOf(v))
		}
	}
	return &domValue{}
}

// invoke runs a user function with the given this and arguments and returns its
// return value. Recursion and depth are capped, so a self-calling function
// cannot loop; a capped call returns its arguments' taint instead.
func (a *domAnalyzer) invoke(fn *domFunc, this *domValue, args []*domValue) *domValue {
	if a.depth >= maxDomDepth || a.active[fn] {
		tainted, origin := anyArgTainted(args)
		return &domValue{tainted: tainted, origin: origin}
	}
	a.depth++
	a.active[fn] = true
	savedCond := a.condDepth
	a.condDepth = 0
	defer func() {
		a.depth--
		delete(a.active, fn)
		a.condDepth = savedCond
	}()

	scope := newDomScope(fn.scope)
	if this != nil {
		scope.vars["this"] = this
	}
	a.bindParams(fn.params, args, scope)

	if fn.exprBody != nil {
		return a.eval(fn.exprBody, scope)
	}
	frame := &domFrame{ret: &domValue{}}
	a.frames = append(a.frames, frame)
	defer func() { a.frames = a.frames[:len(a.frames)-1] }()
	a.hoist(fn.body, scope)
	a.runStatements(fn.body, scope)
	return frame.ret
}

// bindParams binds call arguments to a function's parameters. A missing
// argument takes its default value, and the rest parameter collects the tail.
func (a *domAnalyzer) bindParams(params *ast.ParameterList, args []*domValue, scope *domScope) {
	if params == nil {
		return
	}
	for i, b := range params.List {
		v := argAt(args, i)
		if i >= len(args) && b.Initializer != nil {
			v = a.eval(b.Initializer, scope)
		}
		a.bindTarget(b.Target, v, scope, true)
	}
	if params.Rest != nil {
		rest := argsFrom(args, len(params.List))
		a.bindTarget(params.Rest, &domValue{tainted: anyTaintedArgs(rest), props: indexedProps(rest)}, scope, true)
	}
}

// --- Argument helpers ----------------------------------------------------------

// unwrapOptional returns the expression inside an optional-chain wrapper.
func unwrapOptional(e ast.Expression) ast.Expression {
	switch x := e.(type) {
	case *ast.OptionalChain:
		return unwrapOptional(x.Expression)
	case *ast.Optional:
		return unwrapOptional(x.Expression)
	}
	return e
}

// argAt returns args[i], or an empty value when the argument is absent.
func argAt(args []*domValue, i int) *domValue {
	if i < len(args) && args[i] != nil {
		return args[i]
	}
	return &domValue{}
}

// argsFrom returns the arguments from index i onward.
func argsFrom(args []*domValue, i int) []*domValue {
	if i >= len(args) {
		return nil
	}
	return args[i:]
}

// anyTaintedArgs reports whether any argument is attacker-influenced.
func anyTaintedArgs(args []*domValue) bool {
	tainted, _ := anyArgTainted(args)
	return tainted
}

// indexedProps turns a list into the index-keyed props an array would have.
func indexedProps(list []*domValue) map[string]*domValue {
	out := make(map[string]*domValue, len(list))
	for i, v := range list {
		out[strconv.Itoa(i)] = v
	}
	return out
}

// listArgs expands an array value into the argument list it would pass to
// apply or Reflect.apply. A tainted but unindexed array is one tainted argument.
func listArgs(arr *domValue) []*domValue {
	if arr == nil {
		return nil
	}
	if len(arr.props) == 0 {
		if taintOf(arr) {
			return []*domValue{{tainted: true, origin: originOf(arr)}}
		}
		return nil
	}
	maxIdx := -1
	for k := range arr.props {
		if n, err := strconv.Atoi(k); err == nil && n > maxIdx {
			maxIdx = n
		}
	}
	out := make([]*domValue, maxIdx+1)
	for i := range out {
		if v, ok := arr.props[strconv.Itoa(i)]; ok {
			out[i] = v
		} else {
			out[i] = &domValue{tainted: arr.anyTainted, origin: originOf(arr)}
		}
	}
	return out
}

// isCallable reports whether v can be called.
func isCallable(v *domValue) bool {
	return v != nil && (v.fn != nil || v.sink != "" || v.bound != nil || v.class != nil)
}
