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

	// 1. Top-level KPI grid container (.stats-grid)
	topGrid := findTopLevelStatsGrid(doc)
	if topGrid == nil {
		return errors.New("top-level .stats-grid container not found")
	}

	// 2. #vpnBackendsTable and closest enclosing outer .card
	if count := countHTMLNodesByID(doc, "vpnBackendsTable"); count != 1 {
		return fmt.Errorf("expected exactly 1 #vpnBackendsTable element, found %d", count)
	}
	backendsTable := findHTMLNodeByID(doc, "vpnBackendsTable")
	if backendsTable == nil {
		return errors.New("#vpnBackendsTable not found")
	}
	backendsCard := findClosestEnclosingCard(backendsTable)
	if backendsCard == nil {
		return errors.New("closest enclosing .card for #vpnBackendsTable not found")
	}

	// 3. #vpnSessionsTable and closest enclosing outer .card
	if count := countHTMLNodesByID(doc, "vpnSessionsTable"); count != 1 {
		return fmt.Errorf("expected exactly 1 #vpnSessionsTable element, found %d", count)
	}
	sessionsTable := findHTMLNodeByID(doc, "vpnSessionsTable")
	if sessionsTable == nil {
		return errors.New("#vpnSessionsTable not found")
	}
	sessionsCard := findClosestEnclosingCard(sessionsTable)
	if sessionsCard == nil {
		return errors.New("closest enclosing .card for #vpnSessionsTable not found")
	}

	// 4. #vpn-forwarder-card
	if count := countHTMLNodesByID(doc, "vpn-forwarder-card"); count != 1 {
		return fmt.Errorf("expected exactly 1 #vpn-forwarder-card element, found %d", count)
	}
	forwarderCard := findHTMLNodeByID(doc, "vpn-forwarder-card")
	if forwarderCard == nil {
		return errors.New("#vpn-forwarder-card not found")
	}

	sections := []*xhtml.Node{topGrid, backendsCard, sessionsCard, forwarderCard}
	sectionNames := []string{"stats-grid", "backends card", "sessions card", "vpn-forwarder-card"}

	// Assert distinct elements
	for i := 0; i < len(sections); i++ {
		for j := i + 1; j < len(sections); j++ {
			if sections[i] == sections[j] {
				return fmt.Errorf("sections %s and %s resolve to identical element", sectionNames[i], sectionNames[j])
			}
		}
	}

	// Assert no section is a descendant of another
	for i := 0; i < len(sections); i++ {
		for j := 0; j < len(sections); j++ {
			if i != j && isHTMLDescendant(sections[i], sections[j]) {
				return fmt.Errorf("section %s is nested within / descendant of section %s", sectionNames[j], sectionNames[i])
			}
		}
	}

	// Assert all 4 section containers share the exact same immediate parent element
	parent := topGrid.Parent
	if parent == nil {
		return errors.New("top-level .stats-grid has nil parent")
	}
	for i, s := range sections {
		if s.Parent != parent {
			return fmt.Errorf("section %s does not share immediate parent with stats-grid", sectionNames[i])
		}
	}

	// Sibling index sequence in parent container strictly:
	// stats-grid -> backends card -> sessions card -> vpn-forwarder-card
	getSiblingIndex := func(target *xhtml.Node) int {
		idx := 0
		for c := parent.FirstChild; c != nil; c = c.NextSibling {
			if c == target {
				return idx
			}
			idx++
		}
		return -1
	}

	idxStats := getSiblingIndex(topGrid)
	idxBackends := getSiblingIndex(backendsCard)
	idxSessions := getSiblingIndex(sessionsCard)
	idxForwarder := getSiblingIndex(forwarderCard)

	if idxStats == -1 || idxBackends == -1 || idxSessions == -1 || idxForwarder == -1 {
		return errors.New("failed to resolve sibling indices in immediate parent")
	}

	if !(idxStats < idxBackends && idxBackends < idxSessions && idxSessions < idxForwarder) {
		return fmt.Errorf("invalid sibling order: stats-grid=%d, backends-card=%d, sessions-card=%d, vpn-forwarder-card=%d (expected stats < backends < sessions < forwarder)",
			idxStats, idxBackends, idxSessions, idxForwarder)
	}

	return nil
}
