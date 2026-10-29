package client

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// uriRoots are the packages that never build or parse the NIP-47 URI form
// (NIP-CASH and NIP-CW: no URI form anywhere in the cash NIPs).
var uriRoots = []string{
	"nipcash", "nipcash/client", "nipcash/transport", "nipcash/listing",
	"nipCO", "nipCO/client", "nipcw", "nipcw/client",
}

// T12-25: across the import graph of every root, no package of this module
// other than nip47 itself (which defines them) calls nip47's pairing-URI
// parser or builder, or writes the nostr+walletconnect scheme.
func TestNoURIFormInImportGraph(t *testing.T) {
	const module = "github.com/ohstr/nmilat"
	root := goCmd(t, "list", "-m", "-f", "{{.Dir}}")
	var pkgs []string
	for _, r := range uriRoots {
		if _, err := os.Stat(filepath.Join(root, r)); err == nil {
			pkgs = append(pkgs, module+"/"+r)
		}
	}
	args := append([]string{"list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \" \"}}"}, pkgs...)
	checked := 0
	for _, line := range strings.Split(goCmd(t, args...), "\n") {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[0], module+"/") || parts[0] == module+"/nip47" {
			continue
		}
		for _, f := range strings.Fields(parts[2]) {
			checkNoURIForm(t, parts[0], filepath.Join(parts[1], f))
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no file checked")
	}
}

func checkNoURIForm(t *testing.T, pkg, path string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	nip47Name := ""
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == "github.com/ohstr/nmilat/nip47" {
			nip47Name = "nip47"
			if imp.Name != nil {
				nip47Name = imp.Name.Name
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && nip47Name != "" && id.Name == nip47Name &&
				(x.Sel.Name == "ParsePairingURI" || x.Sel.Name == "BuildPairingURI") { // legacy-check: the test refusing them names them
				t.Errorf("%s (%s) calls nip47.%s", fset.Position(x.Pos()), pkg, x.Sel.Name)
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING && strings.Contains(x.Value, "nostr+walletconnect:") {
				t.Errorf("%s (%s) writes the nostr+walletconnect scheme", fset.Position(x.Pos()), pkg)
			}
		}
		return true
	})
}

func goCmd(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}
