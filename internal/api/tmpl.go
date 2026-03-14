package api

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed templates static
var templateFS embed.FS

var tmpl = template.Must(template.ParseFS(templateFS, "templates/*.html"))

var staticFS = func() fs.FS {
	sub, err := fs.Sub(templateFS, "static")
	if err != nil {
		panic(err)
	}
	return sub
}()
