package i18n

// catalog holds the translations of one language, or of one area of it.
// Catalogs are read-only after package initialization (API-4).
type catalog struct {
	// msgs maps an English message to its translation. A key with a
	// context (Printer.TC) is "context\x04message".
	msgs map[string]string
	// plurals maps the English one and other forms to the translation's
	// one, few and many/other forms (CLDR, integers).
	plurals map[pluralKey][3]string
}

// pluralKey is the English one and other forms of a plural message.
type pluralKey struct {
	one, other string
}

// areas are the per-area catalogs of each language, in the order merge
// reads them. Each area file belongs to one group of packages
// (docs/translations.md), so translators of different areas never edit the
// same file.
var areas = [numLangs][]*catalog{
	Ru: {&ruCore, &ruUI, &ruCLI, &ruTUI},
	Sr: {&srCore, &srUI, &srCLI, &srTUI},
}

// catalogs are the merged catalogs, indexed by Lang; English has none.
var catalogs = [numLangs]catalog{
	En: {},
	Ru: merge(areas[Ru]),
	Sr: merge(areas[Sr]),
}

// merge returns one catalog holding the entries of all parts. A key in
// several parts keeps the first part's translation; the tests require the
// translations to be the same.
func merge(parts []*catalog) catalog {
	c := catalog{msgs: map[string]string{}, plurals: map[pluralKey][3]string{}}
	for _, part := range parts {
		for k, v := range part.msgs {
			if _, ok := c.msgs[k]; !ok {
				c.msgs[k] = v
			}
		}
		for k, v := range part.plurals {
			if _, ok := c.plurals[k]; !ok {
				c.plurals[k] = v
			}
		}
	}
	return c
}
