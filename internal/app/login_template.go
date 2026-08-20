package app

const loginHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Telegram Login</title>
  <style nonce="{{ .CSPNonce }}">
    :root {
      color-scheme: light;
      --bg: #f8f9fa;
      --surface: #ffffff;
      --text: #212529;
      --muted: #5c6268;
      --border: #d8dde2;
      --button: #24292f;
      --button-hover: #111418;
      --error: #b42318;
    }
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: sans-serif;
      display: grid;
      place-items: center;
      padding: 24px;
    }
    main {
      width: min(100%, 420px);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 24px;
    }
    .brand {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .bot {
      color: var(--muted);
      font-size: 14px;
      margin-bottom: 20px;
    }
    button {
      width: 100%;
      min-height: 44px;
      border: 0;
      border-radius: 8px;
      background: var(--button);
      color: #ffffff;
      font: inherit;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover {
      background: var(--button-hover);
    }
    button:focus-visible {
      outline: 2px solid currentColor;
      outline-offset: 3px;
    }
    button:disabled {
      cursor: wait;
      opacity: 0.7;
    }
    .status {
      min-height: 20px;
      margin-top: 14px;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.4;
    }
    .status.error {
      color: var(--error);
    }
  </style>
  <script id="telegram-login-script" nonce="{{ .CSPNonce }}" async src="https://oauth.telegram.org/js/telegram-login.js?3"></script>
</head>
<body>
  <main>
    <div class="brand">Telegram Login</div>
    <div class="bot">@{{ .BotName }}</div>
    <button id="login-button" type="button">Log in with Telegram</button>
    <div id="status" class="status" aria-live="polite"></div>
  </main>
  <script nonce="{{ .CSPNonce }}">
    const loginOptions = {
      client_id: Number({{ .BotID | json }}),
      scope: {{ .Scopes | json }},
      nonce: {{ .Nonce | json }}{{ if .Lang }},
      lang: {{ .Lang | json }}{{ end }}
    };
    const authAction = {{ .AuthAction | json }};
    const state = {{ .State | json }};
    const button = document.getElementById("login-button");
    const statusNode = document.getElementById("status");
    const telegramScript = document.getElementById("telegram-login-script");

    function setStatus(message, isError) {
      statusNode.textContent = message || "";
      statusNode.className = isError ? "status error" : "status";
    }

    function setBusy(busy) {
      button.disabled = busy;
      button.setAttribute("aria-busy", busy ? "true" : "false");
    }

    function submitTelegramAuth(result) {
      if (!result || result.error) {
        setBusy(false);
        setStatus(result && result.error ? result.error : "Telegram login was cancelled.", true);
        return;
      }
      if (!result.id_token) {
        setBusy(false);
        setStatus("Telegram did not return an ID token.", true);
        return;
      }
      const form = document.createElement("form");
      form.method = "post";
      form.action = authAction;
      form.hidden = true;
      const tokenInput = document.createElement("input");
      tokenInput.type = "hidden";
      tokenInput.name = "id_token";
      tokenInput.value = result.id_token;
      const stateInput = document.createElement("input");
      stateInput.type = "hidden";
      stateInput.name = "state";
      stateInput.value = state;
      form.appendChild(tokenInput);
      form.appendChild(stateInput);
      document.body.appendChild(form);
      form.submit();
    }

    function openTelegramLogin() {
      if (!window.Telegram || !Telegram.Login || typeof Telegram.Login.auth !== "function") {
        setBusy(false);
        setStatus("Telegram login is unavailable. Please reload and try again.", true);
        return;
      }
      setBusy(true);
      setStatus("Waiting for Telegram...");
      Telegram.Login.auth(loginOptions, submitTelegramAuth);
    }

    button.addEventListener("click", openTelegramLogin);
    telegramScript.addEventListener("error", function () {
      setBusy(false);
      setStatus("Telegram login could not be loaded. Please reload and try again.", true);
    });
    window.addEventListener("load", function () {
      if (window.Telegram && Telegram.Login && typeof Telegram.Login.init === "function") {
        Telegram.Login.init(loginOptions, submitTelegramAuth);
        setTimeout(function () {
          setBusy(true);
          setStatus("Waiting for Telegram...");
          Telegram.Login.auth(loginOptions, submitTelegramAuth);
        }, 100);
      } else {
        setStatus("Telegram login is unavailable. Please reload and try again.", true);
      }
    });
  </script>
</body>
</html>
`
