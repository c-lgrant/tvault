package cmd

import (
	"fmt"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
)

// resolved is a ref turned into a principal. Name is empty when the ref was
// used as an ID without being able to list (no agents:read / keys:manage).
type resolved struct{ ID, Name string }

// label renders "name (id)", or just the id when the name is unknown.
func (r resolved) label() string {
	if r.Name == "" {
		return r.ID
	}
	return fmt.Sprintf("%s (%s)", r.Name, r.ID)
}

func labels(rs []resolved) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.label()
	}
	return out
}

func idsOf(rs []resolved) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	return out
}

type candidate struct{ ID, Name string }

// pickRef applies the resolution rules to one ref against a full listing:
//
//  1. An ID-shaped ref equal to an existing ID resolves to that ID. If it is
//     ALSO the name of a different principal, refuse: guessing would let
//     whoever can name a principal after another's ID capture commands aimed
//     at that ID.
//  2. An ID-shaped ref that matches no ID but exactly one name resolves to
//     that name only for read-only commands; mutating commands refuse.
//  3. Any other ref resolves by exact name. No match passes through so the
//     server reports not-found.
func pickRef(kind, ref string, cands []candidate, mutating bool) (resolved, error) {
	var idMatch *candidate
	var nameMatches []candidate
	for i, c := range cands {
		if c.ID == ref {
			idMatch = &cands[i]
		}
		if c.Name == ref {
			nameMatches = append(nameMatches, c)
		}
	}
	userErr := func(msg, hint string) error {
		return &clierr.CLIError{Kind: clierr.KindUser, Message: msg, Hint: hint}
	}
	if agentIDPattern.MatchString(ref) {
		if idMatch != nil {
			for _, nm := range nameMatches {
				if nm.ID != idMatch.ID {
					return resolved{}, userErr(
						fmt.Sprintf("ambiguous: %q is the id of %s %q and also the name of %s %q (id %s)",
							ref, kind, idMatch.Name, kind, nm.Name, nm.ID),
						"refusing to guess — rename the "+kind+" named "+ref+", or confirm by acting on the other one's id")
				}
			}
			return resolved{ID: idMatch.ID, Name: idMatch.Name}, nil
		}
		if len(nameMatches) == 1 {
			nm := nameMatches[0]
			if mutating {
				return resolved{}, userErr(
					fmt.Sprintf("no %s has id %s; a %s is NAMED %s — use its id %s", kind, ref, kind, ref, nm.ID),
					"pass the id explicitly so the right "+kind+" is changed")
			}
			return resolved{ID: nm.ID, Name: nm.Name}, nil
		}
	}
	switch len(nameMatches) {
	case 0:
		return resolved{ID: ref}, nil
	case 1:
		return resolved{ID: nameMatches[0].ID, Name: nameMatches[0].Name}, nil
	default:
		return resolved{}, userErr(fmt.Sprintf("%d %ss are named %q — use the %s ID", len(nameMatches), kind, ref, kind), "")
	}
}

// resolveRefs resolves every ref against one listing. If listing is denied
// (missing scope), ID-shaped refs are taken as IDs and the server decides;
// any other ref gets a "pass the ID" error.
func resolveRefs(kind, scope string, list func() ([]candidate, error), refs []string, mutating bool) ([]resolved, error) {
	out := make([]resolved, len(refs))
	var cands []candidate
	listed, denied := false, false
	for i, r := range refs {
		if !listed && !denied {
			c, err := list()
			if err != nil {
				var ce *clierr.CLIError
				if !asCLIErr(err, &ce) || ce.Kind != clierr.KindScopeDenied {
					return nil, err
				}
				denied = true
			} else {
				cands, listed = c, true
			}
		}
		if denied {
			if !agentIDPattern.MatchString(r) {
				return nil, &clierr.CLIError{
					Kind: clierr.KindScopeDenied, Scope: scope,
					Message: fmt.Sprintf("cannot look up %s %q by name — listing %ss needs the %s scope; pass the %s ID instead", kind, r, kind, scope, kind),
					Hint:    fmt.Sprintf("use the %s's ID (shown by `tvault %ss ls` in an admin context) in place of its name", kind, kind),
				}
			}
			out[i] = resolved{ID: r}
			continue
		}
		res, err := pickRef(kind, r, cands, mutating)
		if err != nil {
			return nil, err
		}
		out[i] = res
	}
	return out, nil
}

// resolveAgents resolves agent refs (names or IDs). See pickRef for the rules.
func resolveAgents(client *api.Client, refs []string, mutating bool) ([]resolved, error) {
	return resolveRefs("agent", "agents:read", func() ([]candidate, error) {
		agents, err := client.ListAgents()
		if err != nil {
			return nil, err
		}
		cs := make([]candidate, len(agents))
		for i, a := range agents {
			cs[i] = candidate{a.ID, a.Name}
		}
		return cs, nil
	}, refs, mutating)
}

// resolveAgentRefs is resolveAgents returning only IDs, treating the refs as
// mutating (the safe default).
func resolveAgentRefs(client *api.Client, refs []string) ([]string, error) {
	rs, err := resolveAgents(client, refs, true)
	if err != nil {
		return nil, err
	}
	return idsOf(rs), nil
}

// resolveKey resolves a key ref (name or ID). See pickRef for the rules.
func resolveKey(client *api.Client, ref string, mutating bool) (resolved, error) {
	rs, err := resolveRefs("key", "keys:manage", func() ([]candidate, error) {
		keys, err := client.ListKeys()
		if err != nil {
			return nil, err
		}
		cs := make([]candidate, len(keys))
		for i, k := range keys {
			cs[i] = candidate{k.ID, k.Name}
		}
		return cs, nil
	}, []string{ref}, mutating)
	if err != nil {
		return resolved{}, err
	}
	return rs[0], nil
}
