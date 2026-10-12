package model

import (
	"regexp"
	"strings"
	"unicode"
)

// part is one element of a version ordering key. Elements compare by tag
// first, then numerically (num) or lexically (str), mirroring Python tuple
// ordering of (tag, value) pairs.
type part struct {
	tag     int
	numeric bool
	value   string // digits without leading zeros when numeric
}

func numPart(tag int, digits string) part {
	trimmed := strings.TrimLeft(digits, "0")
	return part{tag: tag, numeric: true, value: trimmed}
}

func strPart(tag int, s string) part { return part{tag: tag, value: s} }

func sign(v int) int {
	switch {
	case v > 0:
		return 1
	case v < 0:
		return -1
	}
	return 0
}

func compareNumbers(a, b string) int {
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

func (p part) compare(o part) int {
	if p.tag != o.tag {
		return sign(p.tag - o.tag)
	}
	if p.numeric && o.numeric {
		return compareNumbers(p.value, o.value)
	}
	return strings.Compare(p.value, o.value)
}

// compareParts is lexicographic tuple comparison: a shorter prefix is smaller.
func compareParts(a, b []part) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := a[i].compare(b[i]); c != 0 {
			return c
		}
	}
	return sign(len(a) - len(b))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func dottedParts(value string, lower bool) []part {
	var parts []part
	for _, piece := range strings.Split(value, ".") {
		if isDigits(piece) {
			parts = append(parts, numPart(0, piece))
		} else {
			if lower {
				piece = strings.ToLower(piece)
			}
			parts = append(parts, strPart(1, piece))
		}
	}
	return parts
}

// ---------------------------------------------------------------- SemVer

var semverPattern = regexp.MustCompile(
	`^[vV]?(\d+)\.(\d+)(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

type semverKey struct {
	release    []part
	isRelease  int
	prerelease []part
}

func parseSemver(value string) *semverKey {
	m := semverPattern.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return nil
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	key := &semverKey{release: []part{numPart(0, m[1]), numPart(0, m[2]), numPart(0, patch)}, isRelease: 1}
	if m[4] != "" {
		key.isRelease = 0 // a release is newer than any of its prereleases
		key.prerelease = dottedParts(m[4], true)
	}
	return key
}

func (k *semverKey) compare(o *semverKey) int {
	if c := compareParts(k.release, o.release); c != 0 {
		return c
	}
	if k.isRelease != o.isRelease {
		return sign(k.isRelease - o.isRelease)
	}
	return compareParts(k.prerelease, o.prerelease)
}

// ---------------------------------------------------------------- PEP 440

var pep440Pattern = regexp.MustCompile(`(?i)^\s*v?(?:(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)` +
	`([-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?([0-9]+)?)?` +
	`((?:-([0-9]+))|(?:[-_.]?(post|rev|r)[-_.]?([0-9]+)?))?` +
	`([-_.]?(dev)[-_.]?([0-9]+)?)?)` +
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$`)

// Infinity markers follow packaging's _cmpkey.
const (
	negInf = -1
	finite = 0
	posInf = 1
)

type pep440Key struct {
	epoch   part
	release []part
	preInf  int
	pre     []part
	postInf int
	post    part
	devInf  int
	dev     part
	local   []part // nil = no local segment (sorts first)
}

func number(s string) part {
	if s == "" {
		s = "0"
	}
	return numPart(0, s)
}

func parsePEP440(value string) *pep440Key {
	m := pep440Pattern.FindStringSubmatch(value)
	if m == nil {
		return nil
	}
	key := &pep440Key{epoch: number(m[1])}
	for _, piece := range strings.Split(m[2], ".") {
		key.release = append(key.release, number(piece))
	}
	for len(key.release) > 0 && key.release[len(key.release)-1].value == "" {
		key.release = key.release[:len(key.release)-1]
	}
	hasPre, hasPost, hasDev := m[3] != "", m[6] != "", m[10] != ""
	switch {
	case !hasPre && !hasPost && hasDev:
		key.preInf = negInf
	case !hasPre:
		key.preInf = posInf
	default:
		letter := strings.ToLower(m[4])
		switch letter {
		case "alpha":
			letter = "a"
		case "beta":
			letter = "b"
		case "c", "pre", "preview":
			letter = "rc"
		}
		key.pre = []part{strPart(0, letter), number(m[5])}
	}
	if hasPost {
		n := m[7]
		if n == "" {
			n = m[9]
		}
		key.post = number(n)
	} else {
		key.postInf = negInf
	}
	if hasDev {
		key.dev = number(m[12])
	} else {
		key.devInf = posInf
	}
	if m[13] != "" {
		key.local = []part{}
		for _, piece := range regexp.MustCompile(`[-_.]`).Split(strings.ToLower(m[13]), -1) {
			if isDigits(piece) {
				key.local = append(key.local, numPart(1, piece))
			} else {
				key.local = append(key.local, strPart(0, piece)) // strings sort before numbers
			}
		}
	}
	return key
}

func compareInf(aInf, bInf int, compare func() int) int {
	if aInf != finite || bInf != finite {
		return sign(aInf - bInf)
	}
	return compare()
}

func (k *pep440Key) compare(o *pep440Key) int {
	if c := k.epoch.compare(o.epoch); c != 0 {
		return c
	}
	if c := compareParts(k.release, o.release); c != 0 {
		return c
	}
	if c := compareInf(k.preInf, o.preInf, func() int { return compareParts(k.pre, o.pre) }); c != 0 {
		return c
	}
	if c := compareInf(k.postInf, o.postInf, func() int { return k.post.compare(o.post) }); c != 0 {
		return c
	}
	if c := compareInf(k.devInf, o.devInf, func() int { return k.dev.compare(o.dev) }); c != 0 {
		return c
	}
	switch {
	case k.local == nil && o.local == nil:
		return 0
	case k.local == nil:
		return -1
	case o.local == nil:
		return 1
	}
	return compareParts(k.local, o.local)
}

// ---------------------------------------------------------------- Maven

var mavenQualifiers = map[string]int{
	"alpha": 0, "a": 0, "beta": 1, "b": 1, "milestone": 2, "m": 2,
	"rc": 3, "cr": 3, "snapshot": 4, "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6,
}

type mavenKey struct {
	release   []part
	rank      int
	qualifier string
	tail      []part
}

func isASCIILetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

// mavenTokens splits on separators and on digit/letter transitions.
func mavenTokens(value string) []string {
	var tokens []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			tokens = append(tokens, strings.ToLower(string(current)))
			current = nil
		}
	}
	for _, r := range value {
		if strings.ContainsRune("._+-", r) {
			flush()
			continue
		}
		if n := len(current); n > 0 {
			prev := current[n-1]
			if (unicode.IsDigit(prev) && isASCIILetter(r)) || (isASCIILetter(prev) && unicode.IsDigit(r)) {
				flush()
			}
		}
		current = append(current, r)
	}
	flush()
	return tokens
}

// parseMaven orders common Maven ComparableVersion forms conservatively:
// "sp" is newer than the base release while "rc" is older; unknown
// qualifiers sort after the known set.
func parseMaven(value string) *mavenKey {
	tokens := mavenTokens(strings.TrimSpace(value))
	if len(tokens) == 0 {
		return nil
	}
	key := &mavenKey{}
	index := 0
	for index < len(tokens) && isDigits(tokens[index]) {
		key.release = append(key.release, numPart(0, tokens[index]))
		index++
	}
	for len(key.release) > 1 && key.release[len(key.release)-1].value == "" {
		key.release = key.release[:len(key.release)-1]
	}
	if len(key.release) == 0 {
		key.release = []part{numPart(0, "0")}
	}
	if index == len(tokens) {
		key.rank = mavenQualifiers[""]
		return key
	}
	qualifier := tokens[index]
	rank, known := mavenQualifiers[qualifier]
	if !known {
		rank = 7
		key.qualifier = qualifier
	}
	key.rank = rank
	for _, token := range tokens[index+1:] {
		if isDigits(token) {
			key.tail = append(key.tail, numPart(0, token))
		} else {
			key.tail = append(key.tail, strPart(1, token))
		}
	}
	return key
}

func (k *mavenKey) compare(o *mavenKey) int {
	if c := compareParts(k.release, o.release); c != 0 {
		return c
	}
	if k.rank != o.rank {
		return sign(k.rank - o.rank)
	}
	if c := strings.Compare(k.qualifier, o.qualifier); c != 0 {
		return c
	}
	return compareParts(k.tail, o.tail)
}

// ---------------------------------------------------------------- Debian

func debianOrder(r rune, present bool) int {
	switch {
	case !present:
		return 0
	case r == '~':
		return -1
	case unicode.IsLetter(r):
		return int(r)
	}
	return int(r) + 256
}

// debianPartCompare implements dpkg's verrevcmp for one version component.
func debianPartCompare(leftText, rightText string) int {
	left, right := []rune(leftText), []rune(rightText)
	li, ri := 0, 0
	nonDigit := func(s []rune, i int) bool { return i < len(s) && !unicode.IsDigit(s[i]) }
	for li < len(left) || ri < len(right) {
		for nonDigit(left, li) || nonDigit(right, ri) {
			var lc, rc rune
			lp, rp := nonDigit(left, li), nonDigit(right, ri)
			if lp {
				lc = left[li]
			}
			if rp {
				rc = right[ri]
			}
			if diff := debianOrder(lc, lp) - debianOrder(rc, rp); diff != 0 {
				return sign(diff)
			}
			if lp {
				li++
			}
			if rp {
				ri++
			}
		}
		for li < len(left) && left[li] == '0' {
			li++
		}
		for ri < len(right) && right[ri] == '0' {
			ri++
		}
		ls, rs := li, ri
		for li < len(left) && unicode.IsDigit(left[li]) {
			li++
		}
		for ri < len(right) && unicode.IsDigit(right[ri]) {
			ri++
		}
		ld, rd := string(left[ls:li]), string(right[rs:ri])
		if len(ld) != len(rd) {
			return sign(len(ld) - len(rd))
		}
		if c := strings.Compare(ld, rd); c != 0 {
			return c
		}
	}
	return 0
}

func debianVersion(value string) (epoch, upstream, revision string) {
	epochText, remainder, found := strings.Cut(value, ":")
	if found && isDigits(epochText) {
		epoch = strings.TrimLeft(epochText, "0")
	} else {
		epoch, remainder = "", value
	}
	if i := strings.LastIndex(remainder, "-"); i >= 0 {
		return epoch, remainder[:i], remainder[i+1:]
	}
	return epoch, remainder, "0"
}

func debianCompare(left, right string) int {
	le, lu, lr := debianVersion(left)
	re, ru, rr := debianVersion(right)
	if c := compareNumbers(le, re); c != 0 {
		return c
	}
	if c := debianPartCompare(lu, ru); c != 0 {
		return c
	}
	return debianPartCompare(lr, rr)
}

// ---------------------------------------------------------------- natural

var naturalPart = regexp.MustCompile(`\d+|[A-Za-z]+|~|[^A-Za-z0-9~]+`)

func naturalKey(value string) []part {
	var parts []part
	for _, piece := range naturalPart.FindAllString(strings.TrimSpace(value), -1) {
		switch {
		case piece == "~":
			parts = append(parts, strPart(-1, ""))
		case isDigits(piece):
			parts = append(parts, numPart(1, piece))
		case isASCIILetter(rune(piece[0])):
			parts = append(parts, strPart(2, strings.ToLower(piece)))
		default:
			parts = append(parts, strPart(0, piece))
		}
	}
	return parts
}

// CompareVersions compares common ecosystem versions without choosing a
// false scheme. It returns -1, 0 or 1.
func CompareVersions(left, right, ecosystem string) int {
	if left == right {
		return 0
	}
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "debian", "deb":
		return debianCompare(left, right)
	case "pypi", "python":
		if l, r := parsePEP440(left), parsePEP440(right); l != nil && r != nil {
			return l.compare(r)
		}
	case "maven":
		if l, r := parseMaven(left), parseMaven(right); l != nil && r != nil {
			return l.compare(r)
		}
	default:
		// Prefer SemVer, but tolerate forms such as 2.0.6rc1 when both
		// operands have an unambiguous PEP 440 order.
		if l, r := parseSemver(left), parseSemver(right); l != nil && r != nil {
			return l.compare(r)
		}
		if l, r := parsePEP440(left), parsePEP440(right); l != nil && r != nil {
			return l.compare(r)
		}
	}
	return compareParts(naturalKey(left), naturalKey(right))
}
