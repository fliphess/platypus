// Package page keeps list paging in range. Handlers already only offer the
// sizes and pages they show; this is the same bound at the service boundary,
// so a caller that forgets the handler cannot ask the database for the whole
// table or overflow the offset.
package page

const (
	// MaxSize is the largest page any list serves.
	MaxSize = 1000
	// MaxPage keeps offset arithmetic inside an int32.
	MaxPage = 1_000_000
)

// Clamp returns a page number, page size and row offset that are all in
// range. A size of zero or less means the default.
func Clamp(number, size, defaultSize int) (page, perPage, offset int) {
	number = min(max(number, 1), MaxPage)
	if size <= 0 {
		size = defaultSize
	}
	size = min(size, MaxSize)
	return number, size, (number - 1) * size
}
