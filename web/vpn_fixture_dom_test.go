package web

import (
	"errors"
	"fmt"
	"strings"

	xhtml "golang.org/x/net/html"
)

func findHTMLNodeByID(n *xhtml.Node, id string) *xhtml.Node {
	if id == "" {
		return nil
	}
	if n == nil {
		return nil
	}
	if n.Type == xhtml.ElementNode {
		for _, attr := range n.Attr {
			if attr.Key == "id" && attr.Val == id {
				return n
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if res := findHTMLNodeByID(c, id); res != nil {
			return res
		}
	}
	return nil
}

func getHTMLNodeAttr(n *xhtml.Node, key string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func findHTMLNodesByTag(n *xhtml.Node, tag string) []*xhtml.Node {
	var results []*xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(curr *xhtml.Node) {
		if curr == nil {
			return
		}
		if curr != n && curr.Type == xhtml.ElementNode && curr.Data == tag {
			results = append(results, curr)
			return
		}
		for c := curr.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return results
}

func getHTMLNodeText(n *xhtml.Node) string {
	var b strings.Builder
	var walk func(*xhtml.Node)
	walk = func(curr *xhtml.Node) {
		if curr == nil {
			return
		}
		if curr.Type == xhtml.TextNode {
			b.WriteString(curr.Data)
		}
		for c := curr.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.TrimSpace(b.String())
}

func hasHTMLClass(n *xhtml.Node, className string) bool {
	if n == nil {
		return false
	}
	for _, c := range strings.Fields(getHTMLNodeAttr(n, "class")) {
		if c == className {
			return true
		}
	}
	return false
}

func findClosestEnclosingCard(n *xhtml.Node) *xhtml.Node {
	for curr := n.Parent; curr != nil; curr = curr.Parent {
		if curr.Type == xhtml.ElementNode && hasHTMLClass(curr, "card") {
			return curr
		}
	}
	return nil
}

func isHTMLDescendant(ancestor, node *xhtml.Node) bool {
	if ancestor == nil || node == nil {
		return false
	}
	for curr := node.Parent; curr != nil; curr = curr.Parent {
		if curr == ancestor {
			return true
		}
	}
	return false
}

func countHTMLNodesByID(root *xhtml.Node, id string) int {
	count := 0
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n == nil {
			return
		}
		if n.Type == xhtml.ElementNode && getHTMLNodeAttr(n, "id") == id {
			count++
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return count
}

// validateVPNDashboardDOMOrder validates the diagnostics document's own order.
//
// The VPN subject is three documents now, so there is no single page order to
// check across the health card, the signals, the inventory and the sessions
// table. Each document validates its own sequence here, and the page tests
// assert the other two:
//
//   - overview: the four-signal grid, then the configuration disclosure;
//   - backends: one inventory card;
//   - diagnostics: the health card, then Advanced Diagnostics, then the sessions
//     table. Health is deliberately ABOVE the disclosure, and the disclosure
//     above the sessions, so a collapsed panel never sits above the answer it
//     belongs to.
func validateVPNDashboardDOMOrder(doc *xhtml.Node) error {
	if doc == nil {
		return errors.New("nil document")
	}

	if count := countHTMLNodesByID(doc, "vpn-forwarder-card"); count != 1 {
		return fmt.Errorf("expected exactly 1 #vpn-forwarder-card element, found %d", count)
	}
	healthCard := findHTMLNodeByID(doc, "vpn-forwarder-card")
	if !hasHTMLClass(healthCard, "card") {
		return errors.New("#vpn-forwarder-card must be a .card")
	}
	// The diagnostics document carries no overview signal grid: the signals are the
	// overview's answer, and a second copy here would duplicate them.
	if n := findHTMLNodeWithIDPrefix(doc, "vpn-kpi-"); n != nil {
		return fmt.Errorf("obsolete KPI tile %q must not exist", getHTMLNodeAttr(n, "id"))
	}
	if inside := findHTMLElementByClassWithin(healthCard, "stats-grid"); inside != nil {
		return errors.New("#vpn-forwarder-card must not contain a nested .stats-grid")
	}

	type region struct {
		id   string
		name string
	}
	regions := []region{
		{"vpn-diagnostics", "#vpn-diagnostics"},
		{"vpnSessionsTable", "#vpnSessionsTable"},
	}
	nodes := []*xhtml.Node{healthCard}
	names := []string{"vpn-forwarder-card"}
	for _, r := range regions {
		if count := countHTMLNodesByID(doc, r.id); count != 1 {
			return fmt.Errorf("expected exactly 1 %s element, found %d", r.name, count)
		}
		nodes = append(nodes, findHTMLNodeByID(doc, r.id))
		names = append(names, r.name)
	}

	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			if nodes[i] == nodes[j] {
				return fmt.Errorf("sections %s and %s resolve to identical element", names[i], names[j])
			}
			if isHTMLDescendant(nodes[i], nodes[j]) || isHTMLDescendant(nodes[j], nodes[i]) {
				return fmt.Errorf("section %s is nested within / descendant of %s", names[i], names[j])
			}
		}
	}

	// A table card must be the OUTERMOST card of its region: the sessions table may
	// not be nested inside another card, because then one card owns two regions and
	// the order above is measured through a shared ancestor instead of page order.
	if node := findHTMLNodeByID(doc, "vpnSessionsTable"); node != nil {
		outer := findClosestEnclosingCard(node)
		if outer == nil {
			return errors.New("closest enclosing .card for #vpnSessionsTable not found")
		}
		if inner := findHTMLElementByClassWithin(outer, "card"); inner != nil {
			return errors.New("card owning #vpnSessionsTable must not contain another .card")
		}
	}

	order := documentOrder(doc)
	index := func(n *xhtml.Node) int {
		for i, candidate := range order {
			if candidate == n {
				return i
			}
		}
		return -1
	}
	for i := 1; i < len(nodes); i++ {
		if index(nodes[i-1]) >= index(nodes[i]) {
			return fmt.Errorf("invalid region order: %s must appear before %s", names[i-1], names[i])
		}
	}

	return nil
}

// documentOrder returns every element node in document order.
func documentOrder(root *xhtml.Node) []*xhtml.Node {
	var out []*xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n == nil {
			return
		}
		if n.Type == xhtml.ElementNode {
			out = append(out, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

// findHTMLNodesByAttr returns every element carrying the given attribute.
func findHTMLNodesByAttr(root *xhtml.Node, attr string) []*xhtml.Node {
	var out []*xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n == nil {
			return
		}
		if n.Type == xhtml.ElementNode {
			for _, a := range n.Attr {
				if a.Key == attr {
					out = append(out, n)
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

// findHTMLNodeWithIDPrefix returns the first element whose id starts with prefix.
func findHTMLNodeWithIDPrefix(root *xhtml.Node, prefix string) *xhtml.Node {
	var found *xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n == nil || found != nil {
			return
		}
		if n.Type == xhtml.ElementNode && strings.HasPrefix(getHTMLNodeAttr(n, "id"), prefix) {
			found = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return found
}

// findHTMLElementByClassWithin returns the first element with the given class
// inside root, or nil.
func findHTMLElementByClassWithin(root *xhtml.Node, class string) *xhtml.Node {
	var found *xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n == nil || found != nil {
			return
		}
		if n.Type == xhtml.ElementNode && hasHTMLClass(n, class) {
			found = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	for c := root.FirstChild; c != nil; c = c.NextSibling {
		walk(c)
	}
	return found
}
