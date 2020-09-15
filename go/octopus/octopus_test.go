package main

import (
	"math/big"
	"reflect"
	"testing"
)

func TestSplitNumber(t *testing.T) {
	test := []string{"00", "1", "1011", "DEAD01", "3413", "999"}
	base := []int{10, 10, 2, 16, 10, 10}
	totLen := []int{1, 1, 4, 6, 4, 4}
	expect := [][]int{{0}, {1}, {1, 1, 0, 1}, {1, 0, 13, 10, 14, 13}, {3, 1, 4, 3}, {9, 9, 9, 0}}

	for i := 0; i < len(test); i++ {
		a, _ := new(big.Int).SetString(test[i], base[i])
		got := splitNumber(a, base[i], totLen[i])
		if !reflect.DeepEqual(got, expect[i]) {
			t.Errorf("wanted %v, but got %v", expect[i], got)
		}
	}
}
