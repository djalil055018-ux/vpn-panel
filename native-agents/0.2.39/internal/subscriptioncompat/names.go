package subscriptioncompat

import "strconv"

// Structured clients use display labels as identifiers. Keep saved labels
// intact and disambiguate only the hosts included in this exported document.
func uniqueClientHostNames(hosts []Host, reserved []string) []Host {
	wanted, used := map[string]bool{}, map[string]bool{}
	for _, h := range hosts {
		wanted[h.Name] = true
	}
	for _, name := range reserved {
		used[name] = true
	}
	out := append([]Host(nil), hosts...)
	next := map[string]int{}
	for i := range out {
		base := out[i].Name
		if used[base] {
			n := next[base]
			if n < 2 {
				n = 2
			}
			for {
				name := base + " · " + strconv.Itoa(n)
				n++
				if !used[name] && !wanted[name] {
					out[i].Name = name
					break
				}
			}
			next[base] = n
		}
		used[out[i].Name] = true
	}
	return out
}
