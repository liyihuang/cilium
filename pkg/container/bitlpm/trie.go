// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"container/heap"
)

// Trie is a [non-preemptive] [binary] [trie] that indexes arbitrarily long
// bit-based keys with associated prefix lengths indexed from [most significant bit]
// ("MSB") to [least significant bit] ("LSB") using the
// [longest prefix match algorithm].
//
// A prefix-length (hereafter "prefix"), in a prefix-key pair, represents the
// minimum number of bits (from MSB to LSB) that another comparable key
// must match.
//
// 'K' must implement the Key[K] interface, and should be passed by value for optimum
// performance. If 'K' is a pointer type, its Key[K] methods must accept nil receivers.
//
// Each method's comments describes the mechanism of how the method
// works.
//
// [non-preemptive]: https://en.wikipedia.org/wiki/Preemption_(computing)
// [binary]: https://en.wikipedia.org/wiki/Binary_number
// [trie]: https://en.wikipedia.org/wiki/Trie
// [most significant bit]: https://en.wikipedia.org/wiki/Bit_numbering#Most_significant_bit
// [least significant bit]: https://en.wikipedia.org/wiki/Bit_numbering#Least_significant_bit
// [longest prefix match algorithm]: https://en.wikipedia.org/wiki/Longest_prefix_match
type Trie[K Key[K], T any] interface {
	// ExactLookup returns a value only if the prefix and key
	// match an entry in the Trie exactly.
	//
	// Note: If the prefix argument exceeds the Trie's maximum
	// prefix, it will be set to the Trie's maximum prefix.
	ExactLookup(prefix uint, key K) (v T, ok bool)
	// LongestPrefixMatch returns the longest prefix match for a specific
	// key.
	LongestPrefixMatch(key K) (k K, v T, ok bool)
	// Ancestors iterates over every prefix-key pair that contains
	// the prefix-key argument pair. If the function argument
	// returns false the iteration will stop. Ancestors iterates
	// keys from shortest to longest prefix match (that is, the
	// longest match will be returned last).
	//
	// Note: If the prefix argument exceeds the Trie's maximum
	// prefix, it will be set to the Trie's maximum prefix.
	Ancestors(prefix uint, key K, fn func(uint, K, T) bool)
	// AncestorIterator returns an iterator for ancestors that
	// can be used to produce the 'Next' key/value pair in sequence.
	AncestorIterator(prefix uint, key K) ancestorIterator[K, T]
	// AncestorsLongestPrefixFirst iterates over every prefix-key pair that
	// contains the prefix-key argument pair. If the function argument
	// returns false the iteration will stop. AncestorsLongestPrefixFirst
	// iterates keys from longest to shortest prefix match (that is, the
	// longest matching prefix will be returned first).
	AncestorsLongestPrefixFirst(prefix uint, key K, fn func(uint, K, T) bool)
	// AncestorLongestPrefixFirstIterator returns an iterator for ancestors
	// that can be used to produce the 'Next' key/value pair in sequence,
	// starting from the key with the longest common prefix with 'key'.
	AncestorLongestPrefixFirstIterator(prefix uint, key K) ancestorLPFIterator[K, T]
	// Descendants iterates over every prefix-key pair that is contained
	// by the prefix-key argument pair. If the function argument
	// returns false the iteration will stop. Descendants does **not** iterate
	// over matches in any guaranteed order.
	//
	// Note: If the prefix argument exceeds the Trie's maximum
	// prefix, it will be set to the Trie's maximum prefix.
	Descendants(prefix uint, key K, fn func(uint, K, T) bool)
	// DescendantIterator returns an iterator for descendants
	// that can be used to produce the 'Next' key/value pair in sequence.
	DescendantIterator(prefix uint, key K) descendantIterator[K, T]
	// DescendantsShortestPrefixFirst iterates over every prefix-key pair that is contained by
	// the prefix-key argument pair. If the function argument returns false the iteration will
	// stop. DescendantsShortestPrefixFirst iterates keys starting from shortest prefix, and
	// progressing towards keys with longer prefixes. Keys with equal prefix lengths are not
	// iterated in any particular order.
	DescendantsShortestPrefixFirst(prefix uint, key K, fn func(uint, K, T) bool)
	// DescendantShortestPrefixFirstIterator returns an iterator for descendants
	// that can be used to produce the 'Next' key/value pair in sequence,
	// starting from the key with the shortest common prefix with 'key'.
	DescendantShortestPrefixFirstIterator(prefix uint, key K) descendantSPFIterator[K, T]
	// Upsert updates or inserts the trie with a a prefix, key,
	// and value. The method returns true if the key is new, and
	// false if the key already existed.
	//
	// Note: If the prefix argument exceeds the Trie's maximum
	// prefix, it will be set to the Trie's maximum prefix.
	Upsert(prefix uint, key K, value T) bool
	// Delete removes a key with the exact given prefix and returns
	// false if the key was not found.
	//
	// Note: If the prefix argument exceeds the Trie's maximum
	// prefix, it will be set to the Trie's maximum prefix.
	Delete(prefix uint, key K) bool
	// Len returns the number of entries in the Trie
	Len() uint
	// ForEach iterates over every element of the Trie in no particular
	// order. If the function argument returns false the iteration stops.
	ForEach(fn func(uint, K, T) bool)
}

// Key is an interface that implements all the necessary
// methods to index and retrieve keys.
type Key[K any] interface {
	// CommonPrefix returns the number of bits that
	// are the same between this key and the argument
	// value, starting from MSB.
	CommonPrefix(K) uint
	// BitValueAt returns the value of the bit at an argument
	// index. MSB is 0 and LSB is n-1.
	BitValueAt(uint) uint8
}

// trie is the generic implementation of a bit-trie that can
// accept arbitrary keys conforming to the Key interface.
type trie[K Key[K], T any] struct {
	root      *node[K, T]
	maxPrefix uint
	entries   uint
}

// NewTrie returns a Trie that accepts the Key[K any] interface
// as its key argument. This enables the user of this Trie to
// define their own bit-key.
func NewTrie[K Key[K], T any](maxPrefix uint) Trie[K, T] {
	return &trie[K, T]{
		maxPrefix: maxPrefix,
	}
}

// node represents a specific key and prefix in the trie
type node[K Key[K], T any] struct {
	children     [2]*node[K, T]
	prefixLen    uint
	key          K
	intermediate bool
	value        T
}

// ExactLookup returns a value only if the prefix and key
// match an entry in the Trie exactly.
//
// Note: If the prefix argument exceeds the Trie's maximum
// prefix, it will be set to the Trie's maximum prefix.
func (t *trie[K, T]) ExactLookup(prefixLen uint, k K) (ret T, found bool) {
	prefixLen = min(prefixLen, t.maxPrefix)
	t.traverse(prefixLen, k, func(currentNode *node[K, T]) bool {
		// Only copy node value if exact prefix length is found
		if currentNode.prefixLen == prefixLen {
			ret = currentNode.value
			found = true
			return false // no need to continue
		}
		return true
	})
	return ret, found
}

// LongestPrefixMatch returns the value for the key with the
// longest prefix match of the argument key.
func (t *trie[K, T]) LongestPrefixMatch(k K) (key K, value T, ok bool) {
	var lpmNode *node[K, T]
	t.traverse(t.maxPrefix, k, func(currentNode *node[K, T]) bool {
		lpmNode = currentNode
		return true
	})
	if lpmNode != nil {
		return lpmNode.key, lpmNode.value, true
	}
	return
}

// Ancestors calls the function argument for every prefix/key/value in the trie
// that contains the prefix-key argument pair in order from shortest to longest
// prefix match. If the function argument returns false the iteration stops.
//
// Note: Ancestors sets any prefixLen argument that exceeds the maximum
// prefix allowed by the trie to the maximum prefix allowed by the
// trie.
func (t *trie[K, T]) Ancestors(prefixLen uint, k K, fn func(prefix uint, key K, value T) bool) {
	prefixLen = min(prefixLen, t.maxPrefix)
	t.traverse(prefixLen, k, func(currentNode *node[K, T]) bool {
		return fn(currentNode.prefixLen, currentNode.key, currentNode.value)
	})
}

// ancestorIterator implements Iteraror for ancestor iteration
type ancestorIterator[K Key[K], T any] struct {
	key         K
	prefixLen   uint
	maxPrefix   uint
	currentNode *node[K, T]
}

// AncestorIterator returns an iterator for ancestors.
func (t *trie[K, T]) AncestorIterator(prefixLen uint, k K) ancestorIterator[K, T] {
	return ancestorIterator[K, T]{
		prefixLen:   min(prefixLen, t.maxPrefix),
		key:         k,
		maxPrefix:   t.maxPrefix,
		currentNode: t.root,
	}
}

// Next produces the 'Next' key/value pair in the iteration sequence maintained by 'iter'. 'ok' is
// 'false' when the sequence ends; 'key' and 'value' are returned with empty values in that case.
func (i *ancestorIterator[K, T]) Next() (ok bool, key K, value T) {
	for i.currentNode != nil {
		k := i.key
		prefixLen := i.prefixLen
		currentNode := i.currentNode

		matchLen := currentNode.prefixMatch(prefixLen, k)
		// The current-node does not match.
		if matchLen < currentNode.prefixLen {
			break
		}
		// Skip over intermediate nodes
		if currentNode.intermediate {
			i.currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)]
			continue
		}
		if matchLen == i.maxPrefix {
			i.currentNode = nil
		} else {
			i.currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)]
		}
		return true, currentNode.key, currentNode.value
	}
	return false, key, value
}

// ancestorLPFIterator implements Iteraror for ancestor iteration for longest-prefix-first iteration
// order.
type ancestorLPFIterator[K Key[K], T any] struct {
	stack nodes[K, T]
}

// AncestorLongestPrefixFirstIterator returns an iterator for ancestors
// that can be used to produce the 'Next' key/value pair in sequence,
// starting from the key with the longest common prefix with 'key'.
func (t *trie[K, T]) AncestorLongestPrefixFirstIterator(prefixLen uint, k K) ancestorLPFIterator[K, T] {
	iter := ancestorLPFIterator[K, T]{}
	for currentNode := t.root; currentNode != nil; currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)] {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		// The current-node does not match.
		if matchLen < currentNode.prefixLen {
			break
		}
		// Skip over intermediate nodes
		if currentNode.intermediate {
			continue
		}
		iter.stack.push(currentNode)
		if matchLen == t.maxPrefix {
			break
		}
	}
	return iter
}

// Next produces the 'Next' key/value pair in the iteration sequence maintained by 'iter'. 'ok' is
// 'false' when the sequence ends; 'key' and 'value' are returned with empty values in that case.
func (i *ancestorLPFIterator[K, T]) Next() (ok bool, key K, value T) {
	if len(i.stack) > 0 {
		n := i.stack.pop()
		return true, n.key, n.value
	}
	return false, key, value
}

// descendantIterator implements Iteraror for descendants iteration
type descendantIterator[K Key[K], T any] struct {
	nodes nodes[K, T]
}

// DescendantIterator returns an iterator for descendants
// that can be used to produce the 'Next' key/value pair in sequence.
func (t *trie[K, T]) DescendantIterator(prefixLen uint, k K) descendantIterator[K, T] {
	iter := descendantIterator[K, T]{}
	prefixLen = min(prefixLen, t.maxPrefix)
	currentNode := t.root
	for currentNode != nil {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		// CurrentNode matches the prefix-key argument
		if matchLen >= prefixLen {
			iter.nodes.push(currentNode)
			break
		}
		// currentNode is a leaf and has no children. Calling k.BitValueAt may
		// overrun the key storage.
		if currentNode.prefixLen >= t.maxPrefix {
			break
		}
		currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)]
	}
	return iter
}

// Next produces the 'Next' key/value pair in the iteration sequence maintained by 'iter'. 'ok' is
// 'false' when the sequence ends; 'key' and 'value' are returned with empty values in that case.
func (i *descendantIterator[K, T]) Next() (ok bool, key K, value T) {
	for len(i.nodes) > 0 {
		// pop the latest node
		n := i.nodes.pop()
		// push the children, if any
		if n.children[0] != nil {
			i.nodes.push(n.children[0])
		}
		if n.children[1] != nil {
			i.nodes.push(n.children[1])
		}
		// Skip over intermediate nodes
		if n.intermediate {
			continue
		}
		return true, n.key, n.value
	}
	return false, key, value
}

// descendantSPFIterator implements Iteraror for descendants iteration for shortest-prefix-first
// iteration order.
type descendantSPFIterator[K Key[K], T any] struct {
	heap nodes[K, T]
}

// DescendantsShortestPrefixFirst iterates over every prefix-key pair that is contained by
// the prefix-key argument pair. If the function argument returns false the iteration will
// stop. DescendantsShortestPrefixFirst iterates keys starting from shortest prefix, and
// progressing towards keys with longer prefixes. Keys with equal prefix lengths are not
// iterated in any particular order.
func (t *trie[K, T]) DescendantShortestPrefixFirstIterator(prefixLen uint, k K) descendantSPFIterator[K, T] {
	iter := descendantSPFIterator[K, T]{}
	prefixLen = min(prefixLen, t.maxPrefix)
	currentNode := t.root
	for currentNode != nil {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		// CurrentNode matches the prefix-key argument
		if matchLen >= prefixLen {
			iter.heap.push(currentNode)
			break
		}
		// currentNode is a leaf and has no children. Calling k.BitValueAt may
		// overrun the key storage.
		if currentNode.prefixLen >= t.maxPrefix {
			break
		}
		currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)]
	}
	return iter
}

// Next produces the 'Next' key/value pair in the iteration sequence maintained by 'iter'. 'ok' is
// 'false' when the sequence ends; 'key' and 'value' are returned with empty values in that case.
func (i *descendantSPFIterator[K, T]) Next() (ok bool, key K, value T) {
	for i.heap.Len() > 0 {
		// pop the node with the lowest prefix length from the heap
		n := i.heap.popHeap()
		// push the children, if any, into the heap
		if n.children[0] != nil {
			i.heap.pushHeap(n.children[0])
		}
		if n.children[1] != nil {
			i.heap.pushHeap(n.children[1])
		}
		// Skip over intermediate nodes
		if n.intermediate {
			continue
		}
		return true, n.key, n.value
	}
	return false, key, value
}

func (t *trie[K, T]) AncestorsLongestPrefixFirst(prefixLen uint, k K, fn func(prefix uint, key K, value T) bool) {
	prefixLen = min(prefixLen, t.maxPrefix)
	t.treverse(prefixLen, k, func(currentNode *node[K, T]) bool {
		return fn(currentNode.prefixLen, currentNode.key, currentNode.value)
	})
}

// Descendants calls the function argument for every prefix/key/value in the
// trie that is contained by the prefix-key argument pair. If the function
// argument returns false the iteration stops. Descendants does **not** iterate
// over matches in any guaranteed order.
//
// Note: Descendants sets any prefixLen argument that exceeds the maximum
// prefix allowed by the trie to the maximum prefix allowed by the
// trie.
func (t *trie[K, T]) Descendants(prefixLen uint, k K, fn func(prefix uint, key K, value T) bool) {
	prefixLen = min(prefixLen, t.maxPrefix)
	currentNode := t.root
	for currentNode != nil {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		// CurrentNode matches the prefix-key argument
		if matchLen >= prefixLen {
			currentNode.forEach(fn)
			return
		}
		// currentNode is a leaf and has no children. Calling k.BitValueAt may
		// overrun the key storage.
		if currentNode.prefixLen >= t.maxPrefix {
			return
		}
		currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)]
	}
}

// DescendantsShortestPrefixFirst iterates over every prefix-key pair that is contained by
// the prefix-key argument pair. If the function argument returns false the iteration will
// stop. DescendantsShortestPrefixFirst iterates keys starting from shortest prefix, and
// progressing towards keys with longer prefixes. Keys with equal prefix lengths are not
// iterated in any particular order.
//
// Note: Descendants sets any prefixLen argument that exceeds the maximum
// prefix allowed by the trie to the maximum prefix allowed by the
// trie.
func (t *trie[K, T]) DescendantsShortestPrefixFirst(prefixLen uint, k K, fn func(prefix uint, key K, value T) bool) {
	prefixLen = min(prefixLen, t.maxPrefix)
	currentNode := t.root
	for currentNode != nil {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		// CurrentNode matches the prefix-key argument
		if matchLen >= prefixLen {
			currentNode.forEachShortestPrefixFirst(fn)
			return
		}
		// currentNode is a leaf and has no children. Calling k.BitValueAt may
		// overrun the key storage.
		if currentNode.prefixLen >= t.maxPrefix {
			return
		}
		currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)]
	}
}

// traverse iterates over every prefix-key pair that contains the
// prefix-key argument pair in order from shortest to longest prefix
// match. If the function argument returns false the iteration will stop.
//
// traverse starts at the root node in the trie.
//
// The key and prefix being searched (the "search" key and prefix) are
// compared to the a trie node's key and prefix (the "node" key and
// prefix) to determine the extent to which the keys match (from MSB to
// LSB) up to the **least** specific (or shortest) prefix of the two keys
// (for example, if one of the keys has a prefix length of 2 and the other has
// a prefix length of 3 then the two keys will be compared up to the 2nd bit).
// If the key's match less than the node prefix (that is, the search
// key did not fully match the node key) then the traversal ends.
// If the key's match was greater than or equal to the node prefix
// then the node key is iterated over as a potential match,
// but traversal continues to ensure that there is not a more specific
// (that is, longer) match. The next bit, after the match length (between
// the search key and node key), on the search key is looked up to
// determine which children of the current node to traverse (to
// check if there is a more specific match). If there is no child then
// traversal ends. Otherwise traversal continues.
func (t *trie[K, T]) traverse(prefixLen uint, k K, fn func(currentNode *node[K, T]) bool) {
	for currentNode := t.root; currentNode != nil; currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)] {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		// The current-node does not match.
		if matchLen < currentNode.prefixLen {
			return
		}
		// Skip over intermediate nodes
		if currentNode.intermediate {
			continue
		}
		if !fn(currentNode) || matchLen == t.maxPrefix {
			return
		}
	}
}

// nPointersOnCacheline is the number of 64-bit pointers on a typical 64-byte cacheline.
// While allocations may cross cache line boundaries, it is still a good size to use for
// a minimum allocation when a small number of pointers is likely needed.
const nPointersOnCacheline = 8

// treverse is like traverse, but it calls 'fn' in reverse order, starting from the most specific match
func (t *trie[K, T]) treverse(prefixLen uint, k K, fn func(currentNode *node[K, T]) bool) {
	// stack is used to reverse the order in which nodes are visited.
	// Preallocate space for some pointers to reduce allocations and copies.
	stack := make([]*node[K, T], 0, nPointersOnCacheline)

	for currentNode := t.root; currentNode != nil; currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)] {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		// The current-node does not match.
		if matchLen < currentNode.prefixLen {
			break
		}
		// Skip over intermediate nodes
		if currentNode.intermediate {
			continue
		}
		stack = append(stack, currentNode)
		if matchLen == t.maxPrefix {
			break
		}
	}

	// Call the function for stacked nodes in reverse order, i.e., longest-prefix-match first
	for i := len(stack) - 1; i >= 0; i-- {
		if !fn(stack[i]) {
			return
		}
	}
}

// Upsert inserts or replaces a key and prefix (an "upsert" key and
// prefix) below keys that match it with a smaller (that is, less
// specific) prefix and above keys that match it with a
// more specific (that is "higher") prefix.
//
// Upsert starts with the root key (or "node"). The upsert key and node
// key are compared for the match length between them (see the
// `traverse` comments for details on how this works). If the match
// length is exactly equal to the node prefix then traversal
// continues as the next bit after the match length in the upsert key
// corresponds to one of the two child slots that belong to the node
// key. If the match length is not exactly equal, or there is no child
// to traverse to, or the node prefix is exactly equal to the
// upsert prefix (these conditions are not mutually exclusive) then traversal
// is finished. There are four possible insertion/replacement conditions
// to consider:
//  1. The node key is nil (that is, an empty children "slot"), in which
//     case the previous key iterated over should be the upsert-key's
//     parent. If there is no parent then the node key is now the
//     root node.
//  2. The node key matches the upsert-node to the exact
//     prefix. Then the upsert key should replace the node key.
//  3. The node key matches the upsert key to the upsert prefix,
//     but node prefix is greater than the upsert prefix. In this
//     case the node key will become a child of the upsert key.
//  4. The node key does not match with the upsert key to either
//     the node prefix or the upsert prefix. In this case an
//     intermediate node needs to be inserted that replaces the
//     current position of the node key, but give it a prefix
//     of the match between the upsert key and node key. The
//     node key and upsert key become siblings.
//
// Intermediate keys/nodes:
// Sometimes when a new key is inserted it does not match any key up to
// its own prefix or its closest matching key's prefix. When this
// happens an intermediate node with the common prefix of the upsert
// key and closest match key. The new intermediate key replaces the closest
// match key's position in the trie and takes the closest match key and
// upsert key as children.
//
// For example, assuming a key size of 8 bytes, adding the prefix-keys of
// "0b001/8"(1-1), "0b010/7"(2-3), and "0b100/6"(4-7) would follow this logic:
//
//  1. "0b001/8" gets added first. It becomes the root node.
//  2. "0b010/7" is added. It will match "0b001/8" (the root node) up to
//     6 bits, because "0b010/7"'s 7th bit is 1 and "0b001/8" has 7th bit of 0.
//     In this case, an intermediate node "0b001/6" will be created (the extent
//     to which "0b010/7" and "0b001/8" match). The new intermediate node will
//     have children "0b001/8" (in the 0 slot) and "0b010/7" (in the 1 slot).
//     This new intermediate node become the new root node.
//  3. When "0b100/6" is added it will match the new root (which happens to
//     be an intermediate node) "0b001/6" up to 5 bits. Therefore another
//     intermediate node of "0b001/5" will be created, becoming the new root
//     node. "0b001/6" will become the new intermediate node's child in the
//     0 slot and "0b100/6" will become the other child in the 1 slot.
//     "0b001/5" becomes the new root node.
//
// Note: Upsert sets any "prefixLen" argument that exceeds the maximum
// prefix allowed by the trie to the maximum prefix allowed by the
// trie.
func (t *trie[K, T]) Upsert(prefixLen uint, k K, value T) bool {
	prefixLen = min(prefixLen, t.maxPrefix)
	upsertNode := &node[K, T]{
		prefixLen: prefixLen,
		key:       k,
		value:     value,
	}

	var (
		matchLen uint
		parent   *node[K, T]
		bitVal   uint8
	)

	currentNode := t.root
	for currentNode != nil {
		matchLen = currentNode.prefixMatch(prefixLen, k)
		// The current node does not match the upsert-{prefix,key}
		// or the current node matches to the maximum extent
		// allowable by either the trie or the upsert-prefix.
		if currentNode.prefixLen != matchLen ||
			currentNode.prefixLen == t.maxPrefix ||
			currentNode.prefixLen == prefixLen {
			break
		}
		bitVal = k.BitValueAt(currentNode.prefixLen)
		parent = currentNode
		currentNode = currentNode.children[bitVal]
	}
	t.entries++
	// Empty slot.
	if currentNode == nil {
		if parent == nil {
			t.root = upsertNode
		} else {
			parent.children[bitVal] = upsertNode
		}
		return true
	}
	// There are three cases:
	// 1. The current-node matches the upsert-node to the exact
	//    prefix. Then the upsert-node should replace the current-node.
	// 2. The current-node matches the upsert-node, but the
	//    current-node has a more specific prefix than the
	//    upsert-node. Then the current-node should become a child
	//    of the upsert-node.
	// 3. The current-node does not match with the upsert-node,
	//    but they overlap. Then a new intermediate-node should replace
	//    the current-node with a prefix equal to the overlap.
	//    The current-node and the upsert-node become children
	//    of the new intermediate node.
	//
	//    For example, given two keys, "current" and "upsert":
	//        current: 0b1010/4
	//        upsert:  0b1000/3
	//    A new key of "0b1010/2" would then be added as an intermediate key
	//    (note: the 3rd bit does not matter, but unsetting is an extra
	//    operation that we avoid). "current" would be a child of
	//    intermediate at index "1" and "upsert" would be at index "0".

	// The upsert-node matches the current-node up to the
	// current-node's prefix, replace the current-node.
	if matchLen == currentNode.prefixLen {
		if parent == nil {
			t.root = upsertNode
		} else {
			parent.children[bitVal] = upsertNode
		}

		upsertNode.children[0] = currentNode.children[0]
		upsertNode.children[1] = currentNode.children[1]

		// If we're not replacing an intermediate node
		// then decrement this function's previous
		// increment of `entries`.
		if !currentNode.intermediate {
			t.entries--
			return false // count remains the same as before
		}
		return true
	}

	// The upsert-node matches the current-node up to
	// the upsert-node's prefix, make the current-node
	// a child of the upsert-node.
	if matchLen == prefixLen {
		if parent == nil {
			t.root = upsertNode
		} else {
			parent.children[bitVal] = upsertNode
		}
		bitVal = currentNode.key.BitValueAt(matchLen)
		upsertNode.children[bitVal] = currentNode
		return true
	}
	// The upsert-node does not match the current-node
	// up to the upsert-node's prefix and the current-node
	// does not match the upsert-node up to the
	// current-node's prefix, make the nodes siblings with
	// an intermediate node.
	intermediateNode := &node[K, T]{
		prefixLen:    matchLen,
		key:          currentNode.key,
		intermediate: true,
	}
	if parent == nil {
		t.root = intermediateNode
	} else {
		parent.children[bitVal] = intermediateNode
	}
	if k.BitValueAt(matchLen) == 0 {
		intermediateNode.children[0] = upsertNode
		intermediateNode.children[1] = currentNode
	} else {
		intermediateNode.children[0] = currentNode
		intermediateNode.children[1] = upsertNode
	}
	return true
}

// Delete deletes only keys that match the exact values of the
// prefix length and key arguments.
//
// Delete traverses the trie until it either finds a node key
// that does not match the delete key to the node key's prefix
// (a definitive non-match) or the node key's prefix is equal
// to the delete prefix (a potential deletion). If the delete prefix,
// node prefix, and match length between the keys are equal to
// the same value then the key is deleted from the trie.
//
// Note: Delete sets any prefixLen argument that exceeds the maximum
// prefix allowed by the trie to the maximum prefix allowed by the
// trie.
func (t *trie[K, T]) Delete(prefixLen uint, k K) bool {
	prefixLen = min(prefixLen, t.maxPrefix)

	var (
		grandParent, parent *node[K, T]
		matchLen            uint
		bitVal, prevBitVal  uint8
	)

	currentNode := t.root
	for currentNode != nil {
		// Find to what extent the current node matches with the
		// delete-{prefix,key}.
		matchLen = currentNode.prefixMatch(prefixLen, k)
		// The current-node does not match or it has the same
		// prefix length (the only potential deletion in the
		// trie).
		if currentNode.prefixLen != matchLen ||
			currentNode.prefixLen == prefixLen {
			break
		}
		prevBitVal = bitVal
		bitVal = k.BitValueAt(currentNode.prefixLen)
		// We preserve the grandParent in order
		// to prune intermediate nodes when they
		// are no longer necessary.
		grandParent = parent
		parent = currentNode
		currentNode = currentNode.children[bitVal]
	}
	// Not found, or the current-node does not match
	// the delete-prefix exactly, or the current-node
	// does not match the delete-{prefix,key} lookup,
	// or the current-node is intermediate.
	if currentNode == nil ||
		currentNode.prefixLen != prefixLen ||
		currentNode.prefixLen != matchLen ||
		currentNode.intermediate {
		return false
	}
	t.entries--

	// If this node has two children, we need to keep it as an intermediate
	// node because we cannot migrate both children up the trie.
	if currentNode.children[0] != nil && currentNode.children[1] != nil {
		var emptyT T
		currentNode.intermediate = true
		// Make sure that the value associated with this intermediate
		// node can be GC'd.
		currentNode.value = emptyT
		return true
	}

	// If the parent of the current-node to be deleted is an
	// intermediate-node and the current-node has no children
	// then the parent (intermediate) node can be deleted and
	// its other child promoted up the trie.
	if parent != nil && parent.intermediate &&
		currentNode.children[0] == nil && currentNode.children[1] == nil {
		var saveNode *node[K, T]
		if k.BitValueAt(parent.prefixLen) == 0 {
			saveNode = parent.children[1]
		} else {
			saveNode = parent.children[0]
		}
		parent.children[0] = nil
		parent.children[1] = nil
		if grandParent == nil {
			t.root = saveNode
		} else {
			grandParent.children[prevBitVal] = saveNode
		}
		return true
	}

	// migrate the last child (if any) up the trie.
	if currentNode.children[0] != nil {
		currentNode = currentNode.children[0]
	} else if currentNode.children[1] != nil {
		currentNode = currentNode.children[1]
	} else {
		currentNode = nil
	}
	if parent == nil {
		t.root = currentNode
	} else {
		parent.children[bitVal] = currentNode
	}
	return true
}

func (t *trie[K, T]) Len() uint {
	return t.entries
}

func (t *trie[K, T]) ForEach(fn func(prefix uint, key K, value T) bool) {
	if t.root != nil {
		t.root.forEach(fn)
	}
}

// prefixMatch returns the length that the node key and
// the argument key match, with the limit of the match being
// the lesser of the node-key prefix or the argument-key prefix.
func (n *node[K, T]) prefixMatch(prefix uint, k K) uint {
	limit := min(n.prefixLen, prefix)
	prefixLen := n.key.CommonPrefix(k)
	if prefixLen >= limit {
		return limit
	}
	return prefixLen
}

// forEach calls the argument function for each key and value in
// the subtree rooted at the current node, iterating recursively in depth-first manner.
func (n *node[K, T]) forEach(fn func(prefix uint, key K, value T) bool) {
	if !n.intermediate {
		if !fn(n.prefixLen, n.key, n.value) {
			return
		}
	}
	if n.children[0] != nil {
		n.children[0].forEach(fn)
	}
	if n.children[1] != nil {
		n.children[1].forEach(fn)
	}
}

// nodes implements container/heap for trie nodes
type nodes[K Key[K], T any] []*node[K, T]

// container/heap interface functions
func (nodes nodes[K, T]) Len() int { return len(nodes) }

func (nodes nodes[K, T]) Less(i, j int) bool {
	return nodes[i].prefixLen < nodes[j].prefixLen
}

func (nodes nodes[K, T]) Swap(i, j int) {
	nodes[i], nodes[j] = nodes[j], nodes[i]
}

func (nodes *nodes[K, T]) Push(x any) {
	node := x.(*node[K, T])
	*nodes = append(*nodes, node)
}

func (nodes *nodes[K, T]) Pop() any {
	old := *nodes
	n := len(old)
	node := old[n-1]
	old[n-1] = nil // don't stop the GC from reclaiming the item eventually
	*nodes = old[:n-1]
	return node
}

func (nodes *nodes[K, T]) pop() *node[K, T] {
	n := len(*nodes)
	node := (*nodes)[n-1]
	*nodes = (*nodes)[:n-1]
	return node
}

func (nodes *nodes[K, T]) push(n *node[K, T]) {
	*nodes = append(*nodes, n)
}

// convenience wrappers
func (nodes *nodes[K, T]) pushHeap(n *node[K, T]) {
	heap.Push(nodes, n)
}

func (nodes *nodes[K, T]) popHeap() *node[K, T] {
	return heap.Pop(nodes).(*node[K, T])
}

// forEachShortestPrefixFirst calls the argument function for each key and value in
// trie, iterating from shortest to longest prefix in the trie.
// A heap is used to track each un-visited subtree, starting from the root. Each node in the heap is
// the node with the shortest prefix of the subtree it represents. To iterate in the order
// of increasing prefix lengths, on each round we pop the node with the shortest prefix from the
// heap, visit it, and push its children into the heap.
func (n *node[K, T]) forEachShortestPrefixFirst(fn func(prefix uint, key K, value T) bool) {
	// nodes is a heap used to track the heads of each unvisited subtree. Each node in the heap
	// has the shortest prefix length of any node in the subtree it represents.
	// Preallocate space for some pointers to reduce allocations and copies.
	nodes := make(nodes[K, T], 0, nPointersOnCacheline)
	nodes.pushHeap(n)

	for nodes.Len() > 0 {
		// pop the node with the lowest prefix length from the heap
		n := nodes.popHeap()
		if !n.intermediate {
			if !fn(n.prefixLen, n.key, n.value) {
				return
			}
		}
		// push the children, if any, into the heap
		if n.children[0] != nil {
			nodes.pushHeap(n.children[0])
		}
		if n.children[1] != nil {
			nodes.pushHeap(n.children[1])
		}
	}
}
