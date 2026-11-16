package i18n

// The catalog tests: they parse passh's source (go/ast, no type checking),
// collect every message of a translation call, and check the catalogs
// against them. The package comment lists the calls they recognize.

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode"
)

// Directives in comments.
const (
	wrapperDirective = "i18n:wrapper"
	dynamicDirective = "i18n:dynamic"
)

// callKind is how a recognized call takes its message.
type callKind int

const (
	kindT        callKind = iota + 1 // x.T(msg, args...), wrappers, i18n.Msg
	kindTC                           // x.TC(context, msg, args...)
	kindN                            // x.N(n, one, other, args...)
	kindErrorf                       // i18n.Errorf(format, args...): always formatted
	kindNewError                     // i18n.NewError(msg): plain text
	kindMark                         // i18n.Mark(msg): a key, used later
)

// found is what extraction collected.
type found struct {
	msgs     map[string][]string    // message (with context) -> positions
	plurals  map[pluralKey][]string // plural forms -> positions
	problems []string               // calls the catalogs can't be checked against
}

// wrapper is a function or method marked i18n:wrapper.
type wrapper struct {
	dir      string // its package's folder
	method   bool
	msgIndex int  // the message parameter, receiver excluded
	variadic bool // the message is followed by the variadic args only
	param    string
}

type constDecl struct {
	expr ast.Expr
	file *srcFile
}

type srcFile struct {
	dir     string
	ast     *ast.File
	imports map[string]string // local name -> import path
	dynamic map[int]bool      // lines with an i18n:dynamic comment
}

type extractor struct {
	fset     *token.FileSet
	root     string // module root
	module   string // module path
	skip     string // a folder not to parse (this package)
	files    []*srcFile
	consts   map[string]map[string]constDecl // dir -> name -> declaration
	values   map[string]string               // dir+"."+name -> resolved value
	busy     map[string]bool
	wrappers map[string][]wrapper // name -> declarations
	found    found
}

var extractOnce = sync.OnceValues(extractMessages)

// extracted returns the messages of passh's source, parsed once per test
// binary.
func extracted(t *testing.T) found {
	t.Helper()
	f, err := extractOnce()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// extractMessages extracts the messages of passh: internal/ and cmd/,
// without this package.
func extractMessages() (found, error) {
	root, module, err := moduleRoot()
	if err != nil {
		return found{}, err
	}
	self, err := filepath.Abs(".")
	if err != nil {
		return found{}, err
	}
	return extractTree(root, module, self, "internal", "cmd")
}

// extractTree extracts the messages of the module at root (module path
// module) from the folders tops, without skip and testdata folders.
func extractTree(root, module, skip string, tops ...string) (found, error) {
	x := &extractor{
		fset:     token.NewFileSet(),
		root:     root,
		module:   module,
		skip:     skip,
		consts:   map[string]map[string]constDecl{},
		values:   map[string]string{},
		busy:     map[string]bool{},
		wrappers: map[string][]wrapper{},
		found:    found{msgs: map[string][]string{}, plurals: map[pluralKey][]string{}},
	}
	for _, top := range tops {
		if err := x.parseTree(filepath.Join(root, top)); err != nil {
			return found{}, err
		}
	}
	for _, f := range x.files {
		x.declarations(f)
	}
	for _, f := range x.files {
		x.calls(f)
	}
	sort.Strings(x.found.problems)
	return x.found, nil
}

// moduleRoot finds go.mod above the working directory.
func moduleRoot() (dir, module string, err error) {
	dir, err = os.Getwd()
	if err != nil {
		return "", "", err
	}
	for {
		f, err := os.Open(filepath.Join(dir, "go.mod"))
		if err == nil {
			defer f.Close() // read-only
			s := bufio.NewScanner(f)
			for s.Scan() {
				if m, ok := strings.CutPrefix(s.Text(), "module "); ok {
					return dir, strings.TrimSpace(m), nil
				}
			}
			return "", "", fmt.Errorf("%s/go.mod has no module line", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", fmt.Errorf("no go.mod above the working directory")
		}
		dir = parent
	}
}

// parseTree parses the non-test .go files under dir, except x.skip and
// testdata folders.
func (x *extractor) parseTree(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == x.skip || (path != dir && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), "."))) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		af, err := parser.ParseFile(x.fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		f := &srcFile{dir: filepath.Dir(path), ast: af, imports: map[string]string{}, dynamic: map[int]bool{}}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			name := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			f.imports[name] = p
		}
		for _, cg := range af.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, dynamicDirective) {
					for l := x.fset.Position(c.Pos()).Line; l <= x.fset.Position(c.End()).Line; l++ {
						f.dynamic[l] = true
					}
				}
			}
		}
		x.files = append(x.files, f)
		return nil
	})
}

// i18nPath is this package's import path.
func (x *extractor) i18nPath() string { return x.module + "/internal/i18n" }

// pkgDir returns the folder of a passh import path, or "".
func (x *extractor) pkgDir(importPath string) string {
	rel, ok := strings.CutPrefix(importPath, x.module+"/")
	if !ok {
		return ""
	}
	return filepath.Join(x.root, filepath.FromSlash(rel))
}

func (x *extractor) pos(p token.Pos) string {
	ps := x.fset.Position(p)
	rel, err := filepath.Rel(x.root, ps.Filename)
	if err != nil {
		rel = ps.Filename
	}
	return fmt.Sprintf("%s:%d", rel, ps.Line)
}

func (x *extractor) problemf(p token.Pos, format string, args ...any) {
	x.found.problems = append(x.found.problems, x.pos(p)+": "+fmt.Sprintf(format, args...))
}

// declarations records the package-level constants and the wrappers of f.
func (x *extractor) declarations(f *srcFile) {
	for name, path := range f.imports {
		if name == "." && path == x.i18nPath() {
			x.problemf(f.ast.Package, "dot import of internal/i18n: its calls can't be found")
		}
	}
	for _, d := range f.ast.Decls {
		switch d := d.(type) {
		case *ast.GenDecl:
			if d.Tok != token.CONST {
				continue
			}
			for _, s := range d.Specs {
				vs := s.(*ast.ValueSpec)
				if len(vs.Values) != len(vs.Names) {
					continue
				}
				for i, n := range vs.Names {
					if x.consts[f.dir] == nil {
						x.consts[f.dir] = map[string]constDecl{}
					}
					x.consts[f.dir][n.Name] = constDecl{expr: vs.Values[i], file: f}
				}
			}
		case *ast.FuncDecl:
			if d.Doc == nil || !hasDirective(d.Doc, wrapperDirective) {
				continue
			}
			w := wrapper{dir: f.dir, method: d.Recv != nil, msgIndex: -1}
			idx := 0
			var names []string
			for fi, field := range d.Type.Params.List {
				for _, n := range field.Names {
					names = append(names, n.Name)
					if w.msgIndex < 0 && (n.Name == "format" || n.Name == "msg") {
						w.msgIndex, w.param = idx, n.Name
						_, isVariadic := d.Type.Params.List[len(d.Type.Params.List)-1].Type.(*ast.Ellipsis)
						w.variadic = isVariadic && fi == len(d.Type.Params.List)-2
					}
					idx++
				}
			}
			if w.msgIndex < 0 {
				x.problemf(d.Pos(), "%s is marked %s but has no parameter named format or msg (it has %v)", d.Name.Name, wrapperDirective, names)
				continue
			}
			x.wrappers[d.Name.Name] = append(x.wrappers[d.Name.Name], w)
		}
	}
}

func hasDirective(cg *ast.CommentGroup, directive string) bool {
	for _, c := range cg.List {
		if strings.Contains(c.Text, directive) {
			return true
		}
	}
	return false
}

// calls collects the messages of the recognized calls in f.
func (x *extractor) calls(f *srcFile) {
	for _, d := range f.ast.Decls {
		var fwd string // a wrapper's own message parameter
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Doc != nil && hasDirective(fd.Doc, wrapperDirective) {
			for _, w := range x.wrappers[fd.Name.Name] {
				if w.dir == f.dir {
					fwd = w.param
				}
			}
		}
		ast.Inspect(d, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				x.call(f, call, fwd)
			}
			return true
		})
	}
}

// call handles one call expression.
func (x *extractor) call(f *srcFile, call *ast.CallExpr, fwd string) {
	kind, msgIndex, variadic := x.recognize(f, call)
	if kind == 0 {
		return
	}
	need := msgIndex + 1
	if kind == kindN {
		need = 3
	}
	if len(call.Args) < need {
		return // not one of ours: those calls wouldn't compile
	}
	exempt := func(e ast.Expr) bool {
		if id, ok := e.(*ast.Ident); ok && fwd != "" && id.Name == fwd {
			return true // a wrapper passing its own message on
		}
		line := func(p token.Pos) int { return x.fset.Position(p).Line }
		return f.dynamic[line(call.Pos())] || f.dynamic[line(call.Pos())-1] ||
			f.dynamic[line(e.Pos())] || f.dynamic[line(e.Pos())-1]
	}
	str := func(e ast.Expr) (string, bool) {
		s, ok := x.constString(f, e)
		if !ok && !exempt(e) {
			x.problemf(e.Pos(), "the message is not a string constant; use a literal or constant, or mark the call %s", dynamicDirective)
		}
		return s, ok
	}
	// given is the number of format arguments at the call, -1 when they
	// are spread (args...) or not known.
	given := -1
	if call.Ellipsis == token.NoPos && variadic {
		given = len(call.Args) - need
	}
	switch kind {
	case kindN:
		one, ok1 := str(call.Args[1])
		other, ok2 := str(call.Args[2])
		if !ok1 || !ok2 {
			return
		}
		if !hasLetter(one) && !hasLetter(other) {
			return
		}
		if sig(one) != sig(other) {
			x.problemf(call.Pos(), "the forms %q and %q use different format verbs", one, other)
		}
		x.checkArgs(call, other, given, false)
		k := pluralKey{one, other}
		x.found.plurals[k] = append(x.found.plurals[k], x.pos(call.Pos()))
	case kindTC:
		ctx, ok1 := str(call.Args[0])
		msg, ok2 := str(call.Args[1])
		if !ok1 || !ok2 || !hasLetter(msg) {
			return
		}
		x.checkArgs(call, msg, given, false)
		k := contextKey(ctx, msg)
		x.found.msgs[k] = append(x.found.msgs[k], x.pos(call.Pos()))
	default:
		msg, ok := str(call.Args[msgIndex])
		if !ok || !hasLetter(msg) {
			return
		}
		switch kind {
		case kindNewError:
			if strings.Contains(msg, "%") {
				x.problemf(call.Pos(), "NewError(%q): the message is plain text, a %% in it is kept as is; use Errorf for a format", msg)
			}
		case kindMark:
			// Used later, with or without arguments.
		default:
			x.checkArgs(call, msg, given, kind == kindErrorf)
		}
		x.found.msgs[msg] = append(x.found.msgs[msg], x.pos(call.Pos()))
	}
}

// checkArgs checks that a call passes as many arguments as msg uses.
// Without arguments a message is plain text (T, Msg, wrappers), so it must
// not hold a %; Errorf always formats.
func (x *extractor) checkArgs(call *ast.CallExpr, msg string, given int, alwaysFormat bool) {
	if given < 0 {
		return
	}
	if given == 0 && !alwaysFormat {
		if strings.Contains(msg, "%") {
			x.problemf(call.Pos(), "%q holds a %% but the call has no arguments, so it is printed as is: pass the arguments or drop the %%", msg)
		}
		return
	}
	ds, ok := directives(msg)
	if !ok {
		x.problemf(call.Pos(), "%q is not a valid format", msg)
		return
	}
	if want := argsUsed(ds); want != given {
		x.problemf(call.Pos(), "%q uses %d arguments, the call passes %d", msg, want, given)
	}
}

// recognize tells whether call is a translation call: its kind, the index
// of its message argument, and whether the format arguments follow it.
func (x *extractor) recognize(f *srcFile, call *ast.CallExpr) (callKind, int, bool) {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		name := fn.Sel.Name
		if id, ok := fn.X.(*ast.Ident); ok {
			if path, isPkg := f.imports[id.Name]; isPkg {
				if path == x.i18nPath() {
					switch name {
					case "NewError":
						return kindNewError, 0, false
					case "Errorf":
						return kindErrorf, 0, true
					case "Msg":
						return kindT, 0, true
					case "Mark":
						return kindMark, 0, false
					}
					return 0, 0, false
				}
				if dir := x.pkgDir(path); dir != "" {
					for _, w := range x.wrappers[name] {
						if !w.method && w.dir == dir {
							return kindT, w.msgIndex, w.variadic
						}
					}
				}
				return 0, 0, false
			}
		}
		switch name {
		case "T":
			return kindT, 0, true
		case "TC":
			return kindTC, 1, true
		case "N":
			return kindN, 2, true
		}
		for _, w := range x.wrappers[name] {
			if w.method {
				return kindT, w.msgIndex, w.variadic
			}
		}
	case *ast.Ident:
		for _, w := range x.wrappers[fn.Name] {
			if !w.method && w.dir == f.dir {
				return kindT, w.msgIndex, w.variadic
			}
		}
	}
	return 0, 0, false
}

// constString evaluates e as a string constant: a literal, a
// concatenation, a constant of the file's package or of another passh
// package.
func (x *extractor) constString(f *srcFile, e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return x.constString(f, e.X)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		a, ok1 := x.constString(f, e.X)
		b, ok2 := x.constString(f, e.Y)
		return a + b, ok1 && ok2
	case *ast.Ident:
		return x.constValue(f.dir, e.Name)
	case *ast.SelectorExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			if dir := x.pkgDir(f.imports[id.Name]); dir != "" {
				return x.constValue(dir, e.Sel.Name)
			}
		}
	}
	return "", false
}

func (x *extractor) constValue(dir, name string) (string, bool) {
	key := dir + "." + name
	if v, ok := x.values[key]; ok {
		return v, true
	}
	d, ok := x.consts[dir][name]
	if !ok || x.busy[key] {
		return "", false
	}
	x.busy[key] = true
	v, ok := x.constString(d.file, d.expr)
	delete(x.busy, key)
	if ok {
		x.values[key] = v
	}
	return v, ok
}

// hasLetter reports whether msg has a letter outside its format verbs: a
// message without one ("%s: %v") needs no translation and is no key.
func hasLetter(msg string) bool {
	ds, _ := directives(msg)
	last := 0
	for _, d := range ds {
		if strings.IndexFunc(msg[last:d.start], unicode.IsLetter) >= 0 {
			return true
		}
		last = d.end
	}
	return strings.IndexFunc(msg[last:], unicode.IsLetter) >= 0
}

// sig is the set of argument and verb pairs a format uses, as a string;
// two formats with the same sig take the same arguments the same way.
func sig(format string) string {
	ds, ok := directives(format)
	if !ok {
		return "invalid format"
	}
	var parts []string
	for _, d := range ds {
		for _, s := range d.stars {
			parts = append(parts, fmt.Sprintf("%d*", s+1))
		}
		parts = append(parts, fmt.Sprintf("%d%c", d.arg+1, d.verb))
	}
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), " ")
}

// --- The tests ---

// translatedLangs are the languages with catalogs.
var translatedLangs = []Lang{Ru, Sr}

// areaNames name the area catalogs in messages, in the order of areas.
var areaNames = []string{"core", "ui", "cli", "tui"}

func areaFile(l Lang, i int) string { return l.String() + "_" + areaNames[i] + ".go" }

// reportAll fails t with one line per problem.
func reportAll(t *testing.T, what string, problems []string) {
	t.Helper()
	if len(problems) == 0 {
		return
	}
	sort.Strings(problems)
	t.Errorf("%d %s (docs/translations.md):\n  %s", len(problems), what, strings.Join(problems, "\n  "))
}

// TestMessageCalls: every translation call has a constant message and
// passes the arguments its format uses, so the other tests see every
// message.
func TestMessageCalls(t *testing.T) {
	reportAll(t, "problems with translation calls", extracted(t).problems)
}

// TestCatalogsAreComplete: every message in the code has a ru and a sr
// translation.
func TestCatalogsAreComplete(t *testing.T) {
	f := extracted(t)
	var missing []string
	for _, l := range translatedLangs {
		c := catalogs[l]
		for k, at := range f.msgs {
			if _, ok := c.msgs[k]; !ok {
				missing = append(missing, fmt.Sprintf("%s: no %s translation of %q (add it to %s_<area>.go)", strings.Join(at, ", "), l, k, l))
			}
		}
		for k, at := range f.plurals {
			if _, ok := c.plurals[k]; !ok {
				missing = append(missing, fmt.Sprintf("%s: no %s plural forms of %q/%q", strings.Join(at, ", "), l, k.one, k.other))
			}
		}
	}
	reportAll(t, "missing translations", missing)
}

// TestCatalogsHaveNoStaleKeys: every catalog entry is a message some code
// uses.
func TestCatalogsHaveNoStaleKeys(t *testing.T) {
	f := extracted(t)
	var stale []string
	for _, l := range translatedLangs {
		for i, a := range areas[l] {
			for k := range a.msgs {
				if _, ok := f.msgs[k]; !ok {
					stale = append(stale, fmt.Sprintf("%s: %q is used by no call", areaFile(l, i), k))
				}
			}
			for k := range a.plurals {
				if _, ok := f.plurals[k]; !ok {
					stale = append(stale, fmt.Sprintf("%s: plural %q/%q is used by no call", areaFile(l, i), k.one, k.other))
				}
			}
		}
	}
	reportAll(t, "unused catalog entries", stale)
}

// TestAreaCatalogsAgree: a key in several area files has the same
// translation in each.
func TestAreaCatalogsAgree(t *testing.T) {
	var diff []string
	for _, l := range translatedLangs {
		for i, a := range areas[l] {
			for j, b := range areas[l][i+1:] {
				for k, v := range a.msgs {
					if w, ok := b.msgs[k]; ok && v != w {
						diff = append(diff, fmt.Sprintf("%s and %s translate %q differently: %q, %q", areaFile(l, i), areaFile(l, i+1+j), k, v, w))
					}
				}
				for k, v := range a.plurals {
					if w, ok := b.plurals[k]; ok && v != w {
						diff = append(diff, fmt.Sprintf("%s and %s translate plural %q differently", areaFile(l, i), areaFile(l, i+1+j), k.one))
					}
				}
			}
		}
	}
	reportAll(t, "conflicting translations", diff)
}

// TestTranslationsKeepFormat: every translation uses the same format verbs
// for the same arguments as its English text, keeps its leading and
// trailing white space, isn't empty, and Serbian is in Latin script.
func TestTranslationsKeepFormat(t *testing.T) {
	var bad []string
	check := func(where, english, tr string, l Lang) {
		switch {
		case tr == "":
			bad = append(bad, fmt.Sprintf("%s: the translation of %q is empty", where, english))
			return
		case sig(english) != sig(tr):
			bad = append(bad, fmt.Sprintf("%s: %q uses verbs [%s], its translation %q [%s]", where, english, sig(english), tr, sig(tr)))
		case edges(english) != edges(tr):
			bad = append(bad, fmt.Sprintf("%s: %q and its translation %q differ in leading or trailing white space", where, english, tr))
		}
		if l == Sr && strings.ContainsFunc(tr, func(r rune) bool { return unicode.Is(unicode.Cyrillic, r) }) {
			bad = append(bad, fmt.Sprintf("%s: %q is Serbian in Cyrillic; passh's Serbian is Latin script", where, tr))
		}
	}
	for _, l := range translatedLangs {
		for i, a := range areas[l] {
			for k, v := range a.msgs {
				english := k
				if _, msg, ok := strings.Cut(k, "\x04"); ok {
					english = msg
				}
				check(areaFile(l, i), english, v, l)
			}
			for k, forms := range a.plurals {
				if sig(k.one) != sig(k.other) {
					bad = append(bad, fmt.Sprintf("%s: the English forms %q and %q use different verbs", areaFile(l, i), k.one, k.other))
				}
				for _, form := range forms {
					check(areaFile(l, i), k.other, form, l)
				}
			}
		}
	}
	reportAll(t, "translations that change the format", bad)
}

// edges is the leading and trailing white space of s.
func edges(s string) string {
	inner := strings.TrimSpace(s)
	if inner == "" {
		return s
	}
	i := strings.Index(s, inner)
	return s[:i] + "…" + s[i+len(inner):]
}
