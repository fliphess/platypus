package page_test

import (
	"testing"

	"platypus/internal/page"
)

// The service boundary bounds what a handler might forget to (Q14).
func TestClamp(t *testing.T) {
	for _, c := range []struct {
		number, size, wantPage, wantSize, wantOffset int
	}{
		{1, 50, 1, 50, 0},
		{0, 0, 1, 25, 0},
		{-5, -1, 1, 25, 0},
		{3, 10, 3, 10, 20},
		{2, 5000, 2, page.MaxSize, page.MaxSize},
		{page.MaxPage + 10, 50, page.MaxPage, 50, (page.MaxPage - 1) * 50},
	} {
		gotPage, gotSize, gotOffset := page.Clamp(c.number, c.size, 25)
		if gotPage != c.wantPage || gotSize != c.wantSize || gotOffset != c.wantOffset {
			t.Errorf("Clamp(%d, %d) = %d, %d, %d; want %d, %d, %d",
				c.number, c.size, gotPage, gotSize, gotOffset, c.wantPage, c.wantSize, c.wantOffset)
		}
	}
}
