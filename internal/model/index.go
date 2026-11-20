package model

import "fmt"

// AssignIndexes gives each Node without an index the next one after
// LastIndex that no Node holds. Indexes are not reused until they wrap, so an
// Agent still on an older snapshot cannot take a new Node for a removed one.
func (n *Network) AssignIndexes() error {
	used := make(map[uint16]bool, len(n.Nodes))
	for _, node := range n.Nodes {
		used[node.Index] = true
	}
	for i := range n.Nodes {
		if n.Nodes[i].Index != 0 {
			continue
		}
		next := n.LastIndex
		for tries := 0; ; tries++ {
			if tries == 1<<16 {
				return fmt.Errorf("network %s: no free node index", n.ID)
			}
			if next++; next != 0 && !used[next] {
				break
			}
		}
		n.Nodes[i].Index, n.LastIndex, used[next] = next, next, true
	}
	return nil
}

func (n *Network) validateIndexes() error {
	used := make(map[uint16]bool, len(n.Nodes))
	for _, node := range n.Nodes {
		if node.Index == 0 || used[node.Index] {
			return fmt.Errorf("network %s: node %s needs a unique nonzero index", n.ID, node.ID)
		}
		used[node.Index] = true
	}
	return nil
}
