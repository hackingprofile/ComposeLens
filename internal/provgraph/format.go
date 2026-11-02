// SPDX-License-Identifier: Apache-2.0

package provgraph

import (
	"bytes"
	"encoding/json"
	"fmt"

	"composelens/internal/redact"
	"composelens/internal/version"
)

const (
	Schema     = "composelens.graph.v0"
	Disclaimer = "whole-model provenance graph assembled from existing stage outputs — not a new resolver, not an engine differential"
)

type Report struct {
	Schema     string       `json:"schema"`
	Product    string       `json:"product"`
	Version    string       `json:"version"`
	Disclaimer string       `json:"disclaimer"`
	Nodes      []NodeReport `json:"nodes"`
	Counts     Counts       `json:"counts"`
	Evidence   string       `json:"evidence"`
	Certainty  string       `json:"certainty"`
}

type NodeReport struct {
	Target      string       `json:"target"`
	Kind        string       `json:"kind"`
	State       string       `json:"state"`
	Effective   *string      `json:"effective,omitempty"`
	Secret      bool         `json:"secret"`
	FinalStage  string       `json:"finalStage,omitempty"`
	Reason      string       `json:"reason,omitempty"`
	ShadowChain []LinkReport `json:"shadowChain"`
	Certainty   string       `json:"certainty"`
	Evidence    string       `json:"evidence"`
}

type LinkReport struct {
	Order     int    `json:"order"`
	Role      string `json:"role"`
	Stage     string `json:"stage"`
	Kind      string `json:"kind,omitempty"`
	Source    string `json:"source,omitempty"`
	State     string `json:"state,omitempty"`
	Secret    bool   `json:"secret"`
	Certainty string `json:"certainty,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
}

type Counts struct {
	Services int `json:"services"`
	Fields   int `json:"fields"`
	Env      int `json:"env"`
	Include  int `json:"include,omitempty"`
	Total    int `json:"total"`
}

func NewReport(g Graph) Report {
	nodes := make([]NodeReport, 0, len(g.Nodes))
	var c Counts
	for _, n := range g.Nodes {
		var eff *string
		if !n.Secret {
			v := n.Effective
			eff = &v
		}
		links := make([]LinkReport, 0, len(n.Chain))
		for _, l := range n.Chain {
			src := l.Source
			if l.Secret && redact.LooksLikeSecret(src) {
				src = "[redacted]"
			}
			links = append(links, LinkReport{
				Order: l.Order, Role: l.Role, Stage: l.Stage, Kind: l.Kind, Source: src,
				State: l.State, Secret: l.Secret, Certainty: l.Certainty, Evidence: l.Evidence,
			})
		}
		nodes = append(nodes, NodeReport{
			Target: n.Target, Kind: n.Kind, State: n.State, Effective: eff, Secret: n.Secret,
			FinalStage: n.FinalStage, Reason: n.Reason, ShadowChain: links,
			Certainty: n.Certainty, Evidence: n.Evidence,
		})
		switch n.Kind {
		case KindService:
			c.Services++
		case KindField:
			c.Fields++
		case KindEnv:
			c.Env++
		case KindInclude:
			c.Include++
		}
	}
	c.Total = len(nodes)
	return Report{
		Schema: Schema, Product: version.Name, Version: version.Version, Disclaimer: Disclaimer,
		Nodes: nodes, Counts: c, Evidence: g.Evidence, Certainty: g.Certainty,
	}
}

func JSON(g Graph) ([]byte, error) {
	return json.MarshalIndent(NewReport(g), "", "  ")
}

func Human(g Graph) string {
	rep := NewReport(g)
	var b bytes.Buffer
	fmt.Fprintf(&b, "ComposeLens provenance graph — %s\n\n", rep.Disclaimer)
	fmt.Fprintf(&b, "nodes: %d  services: %d  fields: %d  env: %d\n", rep.Counts.Total, rep.Counts.Services, rep.Counts.Fields, rep.Counts.Env)
	if rep.Counts.Total == 0 {
		fmt.Fprintf(&b, "  (none)\n")
		return b.String()
	}
	for i, n := range rep.Nodes {
		fmt.Fprintf(&b, "  %d. %s  %s  state=%s\n", i+1, display(n.Target), n.Kind, n.State)
		if n.Secret {
			fmt.Fprintf(&b, "     effective: [redacted]\n")
		} else if n.Effective != nil {
			fmt.Fprintf(&b, "     effective: %s\n", display(*n.Effective))
		}
		if len(n.ShadowChain) == 0 {
			fmt.Fprintf(&b, "     chain: (none)\n")
			continue
		}
		fmt.Fprintf(&b, "     chain:\n")
		for _, l := range n.ShadowChain {
			fmt.Fprintf(&b, "       %d. %s  %s  %s\n", l.Order, l.Role, l.Stage, display(l.Source))
		}
	}
	return b.String()
}

func display(s string) string {
	return redact.DisplayHuman(s)
}
