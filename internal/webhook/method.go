// Package webhook generates and manages a user's Token Vault webhook
// deployment: the Docker Compose project, the local container lifecycle, and
// the browser-free bind handshake.
package webhook

// Method is one webhook exposure method the generator can scaffold.
type Method struct {
	ID          string  // stable id: "ngrok" | "cloudflare" | "tailscale" | "custom"
	Label       string  // display name
	Description string  // one-line summary shown in the wizard
	HelpURL     string  // "more help" link shown in the wizard
	Params      []Param // values the user must supply, in prompt order
}

// Param is one user-supplied value for a Method, written into the project .env.
type Param struct {
	Key       string              // .env key, e.g. "NGROK_AUTHTOKEN"
	Prompt    string              // wizard prompt text
	Help      string              // one-line hint shown with the prompt
	Secret    bool                // true → value is a credential
	Normalize func(string) string // optional; applied to wizard input AND --set values so both paths agree
}

var methods = []Method{
	{
		ID:          "ngrok",
		Label:       "ngrok",
		Description: "ngrok tunnel with a reserved static domain.",
		HelpURL:     "https://dashboard.ngrok.com/cloud-edge/domains",
		Params: []Param{
			{Key: "NGROK_AUTHTOKEN", Prompt: "ngrok authtoken", Help: "from https://dashboard.ngrok.com/get-started/your-authtoken", Secret: true},
			{Key: "NGROK_URL", Prompt: "ngrok static domain", Help: "e.g. your-name.ngrok-free.app — paste with or without https://", Normalize: stripScheme},
		},
	},
	{
		ID:          "cloudflare",
		Label:       "Cloudflare Tunnel",
		Description: "cloudflared named tunnel. Free, robust, needs a Cloudflare account.",
		HelpURL:     "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/",
		Params: []Param{
			{Key: "CLOUDFLARE_TUNNEL_TOKEN", Prompt: "Cloudflare tunnel token", Help: "from the Zero Trust dashboard -> Tunnels", Secret: true},
			{Key: "WEBHOOK_EXTERNAL_URL", Prompt: "public webhook URL", Help: "the public hostname routed to this tunnel — https:// is added if you omit it", Normalize: ensureHTTPS},
		},
	},
	{
		ID:          "tailscale",
		Label:       "Tailscale Funnel",
		Description: "Tailscale Funnel on a stable *.ts.net URL. No custom domain needed.",
		HelpURL:     "https://tailscale.com/kb/1223/funnel",
		Params: []Param{
			{Key: "TS_AUTHKEY", Prompt: "Tailscale auth key", Help: "from https://login.tailscale.com/admin/settings/keys", Secret: true},
			{Key: "TS_HOSTNAME", Prompt: "Tailscale node hostname", Help: "e.g. tv-webhook — becomes <hostname>.<tailnet>.ts.net"},
			{Key: "WEBHOOK_EXTERNAL_URL", Prompt: "public webhook URL", Help: "<hostname>.<tailnet>.ts.net — https:// is added if you omit it", Normalize: ensureHTTPS},
		},
	},
	{
		ID:          "custom",
		Label:       "Custom / already-public",
		Description: "You already host the webhook publicly (VPS, Cloud Run, Fly.io). No tunnel container.",
		HelpURL:     "https://docs.tokenvault.uk/guides/webhook-setup",
		Params: []Param{
			{Key: "WEBHOOK_EXTERNAL_URL", Prompt: "public webhook URL", Help: "the URL your webhook is already reachable at — https:// is added if you omit it", Normalize: ensureHTTPS},
		},
	},
}

// Methods returns all exposure methods in display order.
func Methods() []Method {
	out := make([]Method, len(methods))
	copy(out, methods)
	return out
}

// MethodByID looks up a method by its stable id.
func MethodByID(id string) (Method, bool) {
	for _, m := range methods {
		if m.ID == id {
			return m, true
		}
	}
	return Method{}, false
}
