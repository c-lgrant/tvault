package api

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// appliedVia names the attachment that brought a policy in.
type appliedVia struct {
	Type      string   `json:"type"`
	ID        string   `json:"id"`
	CarriedBy []string `json:"carriedBy"`
}

// denialFields are the POLICY_DENIED extras. AppliedVia and RuleSettings are
// only sent to the owner's own (human) login; agents and scoped keys get
// RetryAfter and maybe EventID instead.
type denialFields struct {
	Policy       string
	Rule         string
	AppliedVia   *appliedVia
	RuleSettings map[string]any
	RetryAfter   *int
	EventID      string
}

func (d *denialFields) explainable() bool {
	return d != nil && (d.AppliedVia != nil || len(d.RuleSettings) > 0)
}

// explainDenial rewrites cliErr in plain words. A POLICY_DENIED carrying
// appliedVia/ruleSettings becomes a full sentence plus a fix hint. Without
// them (an agent-shaped body, or an older server) the message stays what it
// was, with "Try again in Ns." appended when retryAfter is set and a pointer
// to the Activity log when eventId is set. Access refusals get a plain
// sentence and a fix hint whichever server sent them.
func explainDenial(ce *clierr.CLIError, er errorResponse, query map[string]string) {
	switch {
	case er.Code == "POLICY_DENIED" && er.Denial != nil:
		d := er.Denial
		if d.explainable() {
			ce.Plain = policySentence(d, er.Message)
			ce.Hint = policyHint(d)
			return
		}
		if d.RetryAfter != nil && *d.RetryAfter > 0 {
			ce.Message = strings.TrimSpace(ce.Message + " Try again in " + formatSpan(*d.RetryAfter) + ".")
		}
		addEventHint(ce, d.EventID)
	default:
		explainAccess(ce, er, query)
	}
}

func addEventHint(ce *clierr.CLIError, eventID string) {
	if eventID == "" {
		return
	}
	h := "ask the owner to look up event " + eventID + " in Activity"
	if ce.Hint != "" {
		h = ce.Hint + "; " + h
	}
	ce.Hint = h
}

// ── policy sentence ─────────────────────────────────────────────────────────

func policySentence(d *denialFields, reason string) string {
	via := policyBit(d)
	rule := d.RuleSettings
	var s string
	switch d.Rule {
	case "rate_limit":
		limit, secs := num(rule["limit"]), num(rule["windowSeconds"])
		if limit > 0 && secs > 0 {
			s = fmt.Sprintf("rate limit %d requests per %s (%s).", limit, windowPhrase(secs), via)
		} else {
			s = fmt.Sprintf("rate limit reached (%s).", via)
		}
	case "time_window":
		if rule["start"] != nil || rule["days"] != nil {
			start, end := str(rule["start"], "00:00"), str(rule["end"], "23:59")
			hours := formatDays(rule["days"]) + " " + start + "–" + end
			if tz := str(rule["timezone"], ""); tz != "" {
				hours += " " + tz
			}
			s = fmt.Sprintf("outside allowed hours %s (%s).", hours, via)
		} else {
			s = fmt.Sprintf("outside the hours a policy allows (%s).", via)
		}
		if d.RetryAfter != nil {
			s += " Opens again in " + formatSpan(*d.RetryAfter) + "."
		}
	case "max_usage":
		max, used := num(rule["max"]), num(rule["used"])
		if max > 0 {
			if _, ok := rule["used"]; !ok {
				used = max
			}
			s = fmt.Sprintf("lifetime cap reached: used %d of %d (%s). It does not reset by itself.", used, max, via)
		} else {
			s = fmt.Sprintf("lifetime cap reached (%s). It does not reset by itself.", via)
		}
	case "geo_restrict":
		codes := strs(rule["countryCodes"])
		switch {
		case len(codes) == 0:
			s = fmt.Sprintf("country not allowed (%s).", via)
		case rule["mode"] == "deny":
			s = fmt.Sprintf("requests from %s are refused (%s).", joinList(codes), via)
		default:
			s = fmt.Sprintf("country not allowed: only %s may use this (%s).", joinList(codes), via)
		}
	case "ip_allowlist":
		if _, ok := rule["cidrCount"]; ok && num(rule["cidrCount"]) == 0 {
			s = fmt.Sprintf("the IP allowlist is empty, so nobody gets in (%s).", via)
		} else {
			s = fmt.Sprintf("address not on the IP allowlist (%s).", via)
		}
	case "access_channel":
		chans := strs(rule["channels"])
		names := make([]string, len(chans))
		for i, c := range chans {
			names[i] = channelName(c)
		}
		switch {
		case len(chans) == 0:
			s = fmt.Sprintf("this channel is not allowed to read this (%s).", via)
		case rule["mode"] == "deny":
			s = fmt.Sprintf("not allowed from %s (%s).", joinList(names), via)
		default:
			s = fmt.Sprintf("only %s may read this (%s).", joinList(names), via)
		}
	case "manual_approval":
		s = fmt.Sprintf("needs approval, and approvals can't be asked for yet (%s).", via)
	default:
		kind := ""
		if d.Rule != "" {
			kind = " (" + strings.ReplaceAll(d.Rule, "_", " ") + ")"
		}
		s = fmt.Sprintf("denied by %s%s.", via, kind)
		if reason != "" {
			s += " " + reason
		}
	}
	if d.Rule == "rate_limit" && d.RetryAfter != nil {
		s += " Try again in " + formatSpan(*d.RetryAfter) + "."
	}
	if c := carried(d.AppliedVia); c != "" {
		s += " " + c
	}
	return s
}

func policyBit(d *denialFields) string {
	name := "a policy"
	if d.Policy != "" {
		name = "policy " + d.Policy
	}
	if on := attachedTo(d.AppliedVia); on != "" {
		return name + ", on " + on
	}
	return name
}

func attachedTo(v *appliedVia) string {
	if v == nil {
		return ""
	}
	switch v.Type {
	case "agent":
		return "agent " + v.ID
	case "api_key":
		return "key " + v.ID
	case "token":
		return "credential " + v.ID
	case "token_group":
		return "folder " + v.ID
	case "proxy":
		return "proxy " + v.ID
	case "mcp_server":
		return "MCP server " + strings.Replace(v.ID, ":", "/", 1)
	case "label":
		return "label " + v.ID
	}
	return strings.TrimSpace(v.Type + " " + v.ID)
}

func carried(v *appliedVia) string {
	if v == nil || v.Type != "label" || len(v.CarriedBy) == 0 {
		return ""
	}
	names := make([]string, len(v.CarriedBy))
	for i, t := range v.CarriedBy {
		switch t {
		case "token":
			names[i] = "the credential"
		case "api_key":
			names[i] = "the key"
		default:
			names[i] = "the " + t
		}
	}
	return "The label is on " + joinList(names) + "."
}

// policyHint turns appliedVia into the CLI command that detaches the policy,
// where the CLI can; else it points at the console. The policy is named, not
// numbered, in the body, so the id comes from the console's policy list.
func policyHint(d *denialFields) string {
	flag := ""
	if v := d.AppliedVia; v != nil {
		switch v.Type {
		case "label":
			flag = "--label " + v.ID
		case "token":
			flag = "--credential " + v.ID
		case "agent":
			flag = "--agent " + v.ID
		case "api_key":
			flag = "--key " + v.ID
		}
	}
	name := "the policy"
	if d.Policy != "" {
		name = "policy " + d.Policy
	}
	if flag != "" {
		return fmt.Sprintf("to loosen it, edit %s in the web console, or run `tvault policy detach <policy-id> %s`", name, flag)
	}
	return fmt.Sprintf("to loosen it, edit or detach %s in the web console (Policies)", name)
}

// ── access refusals ─────────────────────────────────────────────────────────

func explainAccess(ce *clierr.CLIError, er errorResponse, query map[string]string) {
	cred := query["service"]
	if cred == "" {
		cred = "<credential>"
	}
	name := cred
	if query["service"] == "" {
		name = "that credential"
	}
	switch er.Code {
	case "NO_GRANT":
		ce.Plain = "no access to " + name + ": this key or agent was never granted it."
		ce.Hint = "grant it with `tvault grant <agent> " + cred + "=value` (a key: `tvault keys grant <key> " + cred + "`)"
	case "GRANT_EXPIRED":
		ce.Plain = "access to " + name + " has expired and was removed."
		ce.Hint = "grant it again with `tvault grant <agent> " + cred + "=value`"
	case "GRANT_TOOLS_ONLY":
		ce.Plain = "access to " + name + " allows tool calls only, not reading the value."
		ce.Hint = "add the value use: `tvault grant <agent> " + cred + "=value`"
	case "AGENT_INACTIVE":
		ce.Plain = "this agent is suspended, so every call is refused."
		ce.Hint = "resume it from an admin context: `tvault agents resume <agent>`"
	case "VAULT_LOCKED":
		ce.Plain = "the vault is locked (the kill switch is on), so every call is refused."
		ce.Hint = "the owner can turn access back on with `tvault vault unlock`"
	case "SCOPE_DENIED":
		if er.MissingScope != "" {
			ce.Plain = "this key lacks a permission this call needs: " + er.MissingScope + "."
		} else if er.Message != "" {
			ce.Plain = "this key lacks a permission this call needs: " + er.Message
		} else {
			ce.Plain = "this key lacks a permission this call needs."
		}
		// keep the hint the status switch already set
	case "RATE_LIMITED":
		ce.Plain = "calling faster than Token Vault allows. This is its own safety limit, not one of your policies."
		// the 429 block sets the retry hint
	case "WEBHOOK_CIRCUIT_OPEN":
		ce.Plain = "your webhook has been failing, so Token Vault stopped calling it."
		ce.Hint = "fix the webhook, then retry; `tvault webhook status` shows its state"
	}
}

// ── small formatters ────────────────────────────────────────────────────────

var dayNames = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

// formatSpan renders seconds the way the web console does: 12s, 5 min, 3 h, 2 days.
func formatSpan(seconds int) string {
	if seconds < 0 {
		seconds = 0
	}
	switch {
	case seconds < 90:
		return strconv.Itoa(seconds) + "s"
	case seconds < 5400:
		return strconv.Itoa((seconds+30)/60) + " min"
	case seconds < 2*86400:
		return strconv.Itoa((seconds+1800)/3600) + " h"
	}
	return strconv.Itoa((seconds+43200)/86400) + " days"
}

func windowPhrase(seconds int) string {
	switch seconds {
	case 1:
		return "second"
	case 60:
		return "minute"
	case 3600:
		return "hour"
	case 86400:
		return "day"
	}
	return formatSpan(seconds)
}

func formatDays(v any) string {
	set := map[int]bool{}
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if n := num(x); n >= 1 && n <= 7 {
				set[n] = true
			}
		}
	}
	var list []int
	for d := range set {
		list = append(list, d)
	}
	sort.Ints(list)
	if len(list) == 0 {
		return "no days"
	}
	if len(list) == 7 {
		return "every day"
	}
	var runs []string
	for i := 0; i < len(list); {
		j := i
		for j+1 < len(list) && list[j+1] == list[j]+1 {
			j++
		}
		if j-i >= 2 {
			runs = append(runs, dayNames[list[i]-1]+"–"+dayNames[list[j]-1])
		} else {
			for k := i; k <= j; k++ {
				runs = append(runs, dayNames[list[k]-1])
			}
		}
		i = j + 1
	}
	return strings.Join(runs, ", ")
}

func channelName(c string) string {
	switch c {
	case "web":
		return "the web console"
	case "cli":
		return "the tvault CLI"
	case "agent":
		return "agents"
	case "key":
		return "API keys"
	case "proxy":
		return "MCP proxies"
	}
	return c
}

func joinList(items []string) string {
	switch len(items) {
	case 0:
		return "none"
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func num(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

func str(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func strs(v any) []string {
	a, _ := v.([]any)
	out := make([]string, 0, len(a))
	for _, x := range a {
		out = append(out, fmt.Sprint(x))
	}
	return out
}
