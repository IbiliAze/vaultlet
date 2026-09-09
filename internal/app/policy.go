package app

import (
	"fmt"

	"github.com/IbiliAze/vaultlet/internal/domain"
)

type Action string

const (
	ActionGet    Action = "get"
	ActionList   Action = "list"
	ActionWatch  Action = "watch"
	ActionPut    Action = "put"
	ActionDelete Action = "delete"
)

type Rule struct {
	namespace domain.Namespace
	actions   map[Action]bool
}

type RuleSpec struct {
	Principal, Namespace string
	Actions              []string
}

type Policy map[string][]Rule

// NewPolicy compiles specs into a Policy, rejecting unknown actions and bad
// namespaces so a typo fails at boot rather than becoming a silent denial.
func NewPolicy(specs []RuleSpec) (Policy, error) {
	valid := map[Action]bool{
		ActionGet: true, ActionList: true, ActionWatch: true,
		ActionPut: true, ActionDelete: true,
	}

	p := make(Policy)
	for _, spec := range specs {
		var ns domain.Namespace // zero value: contains every namespace
		if spec.Namespace != "*" {
			parsed, err := domain.ParseNamespace(spec.Namespace)
			if err != nil {
				return nil, fmt.Errorf("policy: user %q: %w", spec.Principal, err)
			}
			ns = parsed
		}

		actions := make(map[Action]bool, len(spec.Actions))
		for _, a := range spec.Actions {
			if !valid[Action(a)] {
				return nil, fmt.Errorf("policy: user %q: unknown action %q", spec.Principal, a)
			}
			actions[Action(a)] = true
		}

		p[spec.Principal] = append(p[spec.Principal], Rule{namespace: ns, actions: actions})
	}
	return p, nil
}

// allows reports whether any of the principal's rules grants action at or
// above ns. No rule, no access.
func (p Policy) allows(principal string, action Action, ns domain.Namespace) bool {
	for _, r := range p[principal] {
		if r.actions[action] && r.namespace.Contains(ns) {
			return true
		}
	}
	return false
}

// canList reports whether the requested namespace overlaps
// any namespace the principal has permission to list.
func (p Policy) canList(principal string, ns domain.Namespace) bool {
	for _, r := range p[principal] {
		if !r.actions[ActionList] {
			continue
		}

		if r.namespace.Contains(ns) || ns.Contains(r.namespace) {
			return true
		}
	}
	return false
}

func (p Policy) canWatch(principal string, ns domain.Namespace) bool {
	for _, r := range p[principal] {
		if !r.actions[ActionWatch] {
			continue
		}

		if r.namespace.Contains(ns) || ns.Contains(r.namespace) {
			return true
		}
	}
	return false
}

func (p Policy) canWatchOrList(principal string, ns domain.Namespace) bool {
	return p.canWatch(principal, ns) || p.canList(principal, ns)
}
