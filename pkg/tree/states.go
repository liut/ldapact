package tree

// Tree branch states (F1 loading/empty/deep/error).
const (
	// StatusEmpty renders "(no children)".
	StatusEmpty = "empty"
	// StatusInaccessible renders "(inaccessible)" with aria-disabled.
	StatusInaccessible = "inaccessible"
)
