package cmd

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:     "whoami",
	Aliases: []string{"who"},
	Short:   "Show the active context, principal, kind, scopes, and expiry",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}

		// Admin contexts refreshed their ID token in resolve(), so a real
		// session expiry is available locally.
		tokenLine := ""
		if cc.Ctx.Type == "admin" {
			_, expiresAt := cc.Ctx.IDToken()
			tokenLine = time.Until(time.Unix(expiresAt, 0)).Round(time.Second).String()
		}

		who, err := cc.Client.Whoami()
		if err != nil {
			// Servers that predate scoped keys don't know /api/agents/whoami
			// for human sessions (404, or INVALID_KEY because they parse the
			// Firebase bearer as an agent key). Fall back to the local-only
			// admin report this command had before scoped keys. Key and agent
			// contexts have no such fallback: their errors are real.
			if cc.Ctx.Type != "admin" || !serverPredatesWhoami(err) {
				return enrich(cmd, cc, err)
			}
			who = &api.WhoamiResult{
				Principal: api.Principal{Type: "user", Name: cc.Ctx.Identity},
				Kind:      legacyServerKind,
			}
		}

		// Text stays the default even when piped (whoami predates the
		// auto-JSON-on-pipe convention); JSON only on an explicit --format json.
		if f, _ := cmd.Flags().GetString("format"); f == "json" {
			return writeWhoamiJSON(cc, who, tokenLine)
		}

		cmd.Printf("context  : %s\n", cc.ContextName)
		cmd.Printf("type     : %s\n", cc.Ctx.Type)
		cmd.Printf("identity : %s\n", cc.Ctx.Identity)
		cmd.Printf("api_url  : %s\n", cc.Ctx.APIURL)
		if tokenLine != "" {
			cmd.Printf("token    : expires in %s\n", tokenLine)
		}
		cmd.Printf("principal: %s %s (%s)\n", who.Principal.Type, who.Principal.Name, who.Principal.ID)
		cmd.Printf("kind     : %s\n", orDash(who.Kind))
		if who.Kind == legacyServerKind {
			cmd.Printf("scopes   : none\n")
		} else {
			cmd.Printf("scopes   : %s\n", scopesLabel(who.Scopes))
		}
		cmd.Printf("expires  : %s\n", expiryLabel(who.ExpiresAt))
		return nil
	},
}

const legacyServerKind = "user (server predates scoped keys)"

// serverPredatesWhoami reports whether err is how a pre-scoped-keys server
// answers GET /api/agents/whoami: a 404, or a 401/403 INVALID_KEY.
func serverPredatesWhoami(err error) bool {
	var ce *clierr.CLIError
	if !asCLIErr(err, &ce) {
		return false
	}
	return ce.Code == "INVALID_KEY" || strings.HasPrefix(ce.Response, "404")
}

func writeWhoamiJSON(cc *cmdContext, who *api.WhoamiResult, tokenExpiresIn string) error {
	scopes := who.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	doc := map[string]any{
		"context":   cc.ContextName,
		"type":      cc.Ctx.Type,
		"identity":  cc.Ctx.Identity,
		"apiUrl":    cc.Ctx.APIURL,
		"principal": who.Principal,
		"userId":    who.UserID,
		"kind":      who.Kind,
		"scopes":    scopes,
		"expiresAt": who.ExpiresAt,
	}
	if tokenExpiresIn != "" {
		doc["tokenExpiresIn"] = tokenExpiresIn
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// scopesLabel renders a scope list; an empty list means a full-access
// (classic / human) principal rather than "no access".
func scopesLabel(scopes []string) string {
	if len(scopes) == 0 {
		return "(none listed — unscoped principal)"
	}
	return strings.Join(scopes, ",")
}

func expiryLabel(expiresAt *string) string {
	if expiresAt == nil || *expiresAt == "" {
		return "never"
	}
	return *expiresAt
}

func init() { rootCmd.AddCommand(whoamiCmd) }
