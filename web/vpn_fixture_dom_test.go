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

func findTopLevelStatsGrid(doc *xhtml.Node) *xhtml.Node {
	var walk func(*xhtml.Node) *xhtml.Node
	walk = func(n *xhtml.Node) *xhtml.Node {
		if n == nil {
			return nil
		}
		if n.Type == xhtml.ElementNode && hasHTMLClass(n, "stats-grid") {
			// Top-level KPI grid must not be enclosed inside another card (e.g. forwarder card)
			if findClosestEnclosingCard(n) == nil {
				return n
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if found := walk(c); found != nil {
				return found
			}
		}
		return nil
	}
	return walk(doc)
}

func validateVPNDashboardDOMOrder(doc *xhtml.Node) error {
	if doc == nil {
		return errors.New("nil document")
	}

	// #955 layout: VPN Health first (the answer to "is it working"), then the
	// four-signal overview, then Advanced Diagnostics, the configuration strip and
	// finally the backend and session tables. The health panel is deliberately
	// ABOVE the overview now, and the overview grid is the only .stats-grid on the
	// page: a second one inside #vpn-forwarder-card is exactly what this issue
	// removed.
	if count := countHTMLNodesByID(doc, "vpn-forwarder-card"); count != 1 {
		return fmt.Errorf("expected exactly 1 #vpn-forwarder-card element, found %d", count)
	}
	healthCard := findHTMLNodeByID(doc, "vpn-forwarder-card")
	if healthCard == nil {
		return errors.New("#vpn-forwarder-card not found")
	}
	if !hasHTMLClass(healthCard, "card") {
		return errors.New("#vpn-forwarder-card must be a .card")
	}

	overview := findTopLevelStatsGrid(doc)
	if overview == nil {
		return errors.New("top-level .stats-grid container not found")
	}
	if isHTMLDescendant(overview, healthCard) || isHTMLDescendant(healthCard, overview) {
		return errors.New("the overview grid and #vpn-forwarder-card must not be nested in each other")
	}

	// The health card must carry exactly the four signals, and no KPI tiles.
	signals := findHTMLNodesByAttr(doc, "data-signal")
	if len(signals) != 4 {
		return fmt.Errorf("expected exactly 4 [data-signal] entries, found %d", len(signals))
	}
	for _, signal := range signals {
		if !isHTMLDescendant(overview, signal) {
			return errors.New("[data-signal] entry is not inside the overview grid")
		}
	}
	if n := findHTMLNodeWithIDPrefix(doc, "vpn-kpi-"); n != nil {
		return fmt.Errorf("obsolete KPI tile %q must not exist", getHTMLNodeAttr(n, "id"))
	}
	if inside := findHTMLElementByClassWithin(healthCard, "stats-grid"); inside != nil {
		return errors.New("#vpn-forwarder-card must not contain a nested .stats-grid")
	}

	// Ordered page regions, each appearing exactly once.
	type region struct {
		id   string
		name string
	}
	regions := []region{
		{"vpn-diagnostics", "#vpn-diagnostics"},
		{"vpn-configuration", "#vpn-configuration"},
		{"vpnBackendsTable", "#vpnBackendsTable"},
		{"vpnSessionsTable", "#vpnSessionsTable"},
	}
	nodes := []*xhtml.Node{healthCard, overview}
	names := []string{"vpn-forwarder-card", "overview grid"}
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

	// A table card must be the OUTERMOST card of its region: the backends table may
	// not be nested inside another card that also holds the sessions table, because
	// then one card owns two regions and the section order below would be measured
	// through a shared ancestor instead of real page order.
	for _, id := range []string{"vpnBackendsTable", "vpnSessionsTable"} {
		node := findHTMLNodeByID(doc, id)
		outer := findClosestEnclosingCard(node)
		if outer == nil {
			return fmt.Errorf("closest enclosing .card for #%s not found", id)
		}
		if inner := findHTMLElementByClassWithin(outer, "card"); inner != nil {
			return fmt.Errorf("card owning #%s must not contain another .card", id)
		}
	}

	// Advanced Diagnostics must be ordered after the health card and overview, so
	// a collapsed panel can never sit above the answer it belongs to.
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
