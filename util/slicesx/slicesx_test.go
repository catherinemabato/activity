// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package slicesx

import (
	"reflect"
	"slices"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestInterleave(t *testing.T) {
	testCases := []struct {
		name string
		a, b []int
		want []int
	}{
		{name: "equal", a: []int{1, 3, 5}, b: []int{2, 4, 6}, want: []int{1, 2, 3, 4, 5, 6}},
		{name: "short_b", a: []int{1, 3, 5}, b: []int{2, 4}, want: []int{1, 2, 3, 4, 5}},
		{name: "short_a", a: []int{1, 3}, b: []int{2, 4, 6}, want: []int{1, 2, 3, 4, 6}},
		{name: "len_1", a: []int{1}, b: []int{2, 4, 6}, want: []int{1, 2, 4, 6}},
		{name: "nil_a", a: nil, b: []int{2, 4, 6}, want: []int{2, 4, 6}},
		{name: "nil_all", a: nil, b: nil, want: nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			merged := Interleave(tc.a, tc.b)
			if !reflect.DeepEqual(merged, tc.want) {
				t.Errorf("got %v; want %v", merged, tc.want)
			}
		})
	}
}

func BenchmarkInterleave(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		Interleave(
			[]int{1, 2, 3},
			[]int{9, 8, 7},
		)
	}
}

func TestShuffle(t *testing.T) {
	var sl []int
	for i := range 100 {
		sl = append(sl, i)
	}

	var wasShuffled bool
	for try := 0; try < 10; try++ {
		shuffled := slices.Clone(sl)
		Shuffle(shuffled)
		if !reflect.DeepEqual(shuffled, sl) {
			wasShuffled = true
			break
		}
	}

	if !wasShuffled {
		t.Errorf("expected shuffle after 10 tries")
	}
}

func TestPartition(t *testing.T) {
	var sl []int
	for i := 1; i <= 10; i++ {
		sl = append(sl, i)
	}

	evens, odds := Partition(sl, func(elem int) bool {
		return elem%2 == 0
	})

	wantEvens := []int{2, 4, 6, 8, 10}
	wantOdds := []int{1, 3, 5, 7, 9}
	if !reflect.DeepEqual(evens, wantEvens) {
		t.Errorf("evens: got %v, want %v", evens, wantEvens)
	}
	if !reflect.DeepEqual(odds, wantOdds) {
		t.Errorf("odds: got %v, want %v", odds, wantOdds)
	}
}

func TestEqualSameNil(t *testing.T) {
	c := qt.New(t)
	c.Check(EqualSameNil([]string{"a"}, []string{"a"}), qt.Equals, true)
	c.Check(EqualSameNil([]string{"a"}, []string{"b"}), qt.Equals, false)
	c.Check(EqualSameNil([]string{"a"}, []string{}), qt.Equals, false)
	c.Check(EqualSameNil([]string{}, []string{}), qt.Equals, true)
	c.Check(EqualSameNil(nil, []string{}), qt.Equals, false)
	c.Check(EqualSameNil([]string{}, nil), qt.Equals, false)
	c.Check(EqualSameNil[[]string](nil, nil), qt.Equals, true)
}

func TestFilter(t *testing.T) {
	var sl []int
	for i := 1; i <= 10; i++ {
		sl = append(sl, i)
	}

	evens := Filter(nil, sl, func(elem int) bool {
		return elem%2 == 0
	})

	want := []int{2, 4, 6, 8, 10}
	if !reflect.DeepEqual(evens, want) {
		t.Errorf("evens: got %v, want %v", evens, want)
	}
}

func TestFilterNoAllocations(t *testing.T) {
	var sl []int
	for i := 1; i <= 10; i++ {
		sl = append(sl, i)
	}

	want := []int{2, 4, 6, 8, 10}
	allocs := testing.AllocsPerRun(1000, func() {
		src := slices.Clone(sl)
		evens := Filter(src[:0], src, func(elem int) bool {
			return elem%2 == 0
		})
		if !slices.Equal(evens, want) {
			t.Errorf("evens: got %v, want %v", evens, want)
		}
	})

	// 1 alloc for 'src', nothing else
	if allocs != 1 {
		t.Fatalf("got %.4f allocs, want 1", allocs)
	}
}
