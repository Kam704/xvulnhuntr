package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Result structure for JSON output
type Result struct {
	FilePath string `json:"filepath"`
	Source   string `json:"source"`
	Type     string `json:"type"` // "function" or "struct"
}

// ExtractDefinition extracts either a function or struct definition
func ExtractDefinition(sourceCode, name string) (string, string, error) {
	fs := token.NewFileSet()
	node, err := parser.ParseFile(fs, "", sourceCode, parser.AllErrors)
	if err != nil {
		return "", "", err
	}

	var buf bytes.Buffer

	// Check for function
	for _, decl := range node.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if fn.Name.Name == name {
				printer.Fprint(&buf, fs, fn)
				return buf.String(), "function", nil
			}
		}
	}

	// Check for struct
	buf.Reset() // Clear buffer for next attempt
	for _, decl := range node.Decls {
		if genDecl, ok := decl.(*ast.GenDecl); ok && genDecl.Tok == token.TYPE {
			for _, spec := range genDecl.Specs {
				if typeSpec, ok := spec.(*ast.TypeSpec); ok {
					if typeSpec.Name.Name == name {
						printer.Fprint(&buf, fs, genDecl)
						return buf.String(), "struct", nil
					}
				}
			}
		}
	}

	return "", "", fmt.Errorf("definition %s not found", name)
}

// Extract the function or struct name from a fully qualified identifier (e.g., "middleware.StaticContentsMiddleware" -> "StaticContentsMiddleware")
func ExtractName(qualifiedName string) string {
	parts := strings.Split(qualifiedName, ".")
	return parts[len(parts)-1] // Return only the last part (unqualified name)
}

// SearchGoFiles recursively searches for .go files in a folder and returns the first match
func SearchGoFiles(root, qualifiedName string) (*Result, error) {
	name := ExtractName(qualifiedName) // Extract function or struct name

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Process only .go files
		if !d.IsDir() && filepath.Ext(path) == ".go" {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			extractedCode, defType, err := ExtractDefinition(string(content), name)
			if err == nil { // If found, return the first match immediately
				result := &Result{FilePath: path, Source: extractedCode, Type: defType}
				jsonOutput, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(jsonOutput))
				os.Exit(0) // Terminate after the first match
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("definition %s not found", name)
}

func main() {
	// Get inputs from command-line arguments
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <folder_path> <name>")
		os.Exit(1)
	}

	folderPath := os.Args[1]
	name := os.Args[2]

	_, err := SearchGoFiles(folderPath, name)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	// If no match was found, exit with an error
	os.Exit(1)
}
