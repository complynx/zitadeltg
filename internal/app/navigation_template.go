package app

import "html/template"

// Commit a same-origin document before leaving the form's CSP navigation chain.
// Destination must pass the relay's HTTPS and origin checks before rendering.
var navigationPage = template.Must(template.New("navigation").Funcs(template.FuncMap{"json": templateJSON}).Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Continue sign-in</title></head>
<body>
  <p>Continuing sign-in. <a href="{{ .Destination }}" rel="noreferrer">Continue</a></p>
  <script nonce="{{ .Nonce }}">window.location.replace({{ .Destination | json }});</script>
</body>
</html>`))
