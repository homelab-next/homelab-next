// SPDX-License-Identifier: Apache-2.0

// Package lessons matches a job's task against the lessons and runbooks registers, so the
// prompt of a run carries the register entries that apply to it (ResolveContext).
//
// A record applies only when its match does: a keyword occurs in the task as whole words, or one
// of its paths prefixes a path the job names. Its other signals (quoted spans, systems, title
// words) rank matched records and never make one match.
//
// Only a record that declares a match (the optional `match` field: lesson schema 2.2, runbook
// schema 2.3) is ever matched; a record without one is never injected, whatever its text. A
// match is bounded: a few literal keywords (matched case-insensitively as whole words of the task) and a few
// path prefixes, never a regular expression. A record that matches is scored with its keywords
// and paths, the quoted spans of its title and symptom, its systems and its title's words; the
// best few above a floor are injected. Inactive records (a retired, incorporated or superseded
// lesson, a runbook with superseded_by) are never injected. What reaches the prompt is quoted as
// data, never as instructions (dispatch.go).
package lessons

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Scoring: a keyword hit is worth the most, then a path, a quoted span, a system tag and a title
// word; an entry needs minScore, and at most topK of each register are injected.
const (
	minScore = 3
	topK     = 4
	wKeyword = 5
	wPath    = 4
	wSpan    = 3
	wTag     = 2
	wToken   = 1
)

// Match bounds (the `match` field of the lesson and runbook schemas, which a test holds equal).
const (
	MaxMatchItems    = 16
	MinKeywordLength = 4
	MaxKeywordLength = 80
	MaxPathLength    = 200
)

var stopwords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`a an and are as at be but by can do for from has have how
if in into is it its not of on or that the their then there this to was were what
when which will with without you your never always every one two only own same
means check does did done more most much need needs new now out over some than`) {
		stopwords[w] = true
	}
}

var (
	wordRe = regexp.MustCompile(`[a-z0-9][a-z0-9_.\-]{2,}`)
	spanRe = regexp.MustCompile("[`'\"]([^`'\"]{4,60})[`'\"]")
)

func tokens(text string) map[string]bool {
	out := map[string]bool{}
	for _, m := range wordRe.FindAllString(strings.ToLower(text), -1) {
		if !stopwords[m] {
			out[m] = true
		}
	}
	return out
}

func titleTokens(text string) map[string]bool {
	out := map[string]bool{}
	for t := range tokens(text) {
		if len(t) >= 5 {
			out[t] = true
		}
	}
	return out
}

func spans(text string) []string {
	var out []string
	for _, m := range spanRe.FindAllStringSubmatch(text, -1) {
		out = append(out, strings.ToLower(m[1]))
	}
	return out
}

// MatchDef is a record's `match`: literal keywords and path prefixes.
type MatchDef struct {
	Keywords []string `yaml:"keywords"`
	Paths    []string `yaml:"paths"`
}

// UnmarshalYAML decodes a match strictly: a key other than keywords and paths (a pattern, say)
// is refused, never ignored, and each list holds strings only.
func (m *MatchDef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("match: a mapping of keywords and/or paths")
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		var dst *[]string
		switch key {
		case "keywords":
			dst = &m.Keywords
		case "paths":
			dst = &m.Paths
		default:
			return fmt.Errorf("match: unknown key %q (keywords and paths only; never a pattern)", clip(key))
		}
		if val.Kind != yaml.SequenceNode || len(val.Content) == 0 {
			return fmt.Errorf("match.%s: a non-empty list of strings (leave the key out instead)", key)
		}
		for _, e := range val.Content {
			if e.Kind != yaml.ScalarNode || e.ShortTag() != "!!str" {
				return fmt.Errorf("match.%s: a list of strings", key)
			}
			*dst = append(*dst, e.Value)
		}
	}
	return nil
}

// check holds a match to its bounds: at least one keyword or path, at most MaxMatchItems of each,
// each listed once; a keyword of MinKeywordLength to MaxKeywordLength characters with no control
// character; a path a clean relative prefix of at most MaxPathLength characters.
func (m *MatchDef) check() error {
	if len(m.Keywords)+len(m.Paths) == 0 {
		return fmt.Errorf("match: names no keyword and no path (leave match out instead)")
	}
	if len(m.Keywords) > MaxMatchItems || len(m.Paths) > MaxMatchItems {
		return fmt.Errorf("match: at most %d keywords and %d paths", MaxMatchItems, MaxMatchItems)
	}
	seen := map[string]bool{}
	for _, k := range m.Keywords {
		n := len([]rune(k))
		if n < MinKeywordLength || n > MaxKeywordLength || strings.TrimSpace(k) != k || strings.IndexFunc(k, isControl) >= 0 {
			return fmt.Errorf("match: keyword %q: %d to %d characters, no control character, no surrounding space", clip(k), MinKeywordLength, MaxKeywordLength)
		}
		if seen["k:"+strings.ToLower(k)] {
			return fmt.Errorf("match: keyword %q is listed twice", clip(k))
		}
		seen["k:"+strings.ToLower(k)] = true
	}
	for _, p := range m.Paths {
		clean := filepath.ToSlash(filepath.Clean(p))
		if p == "" || len(p) > MaxPathLength || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.IndexFunc(p, isControl) >= 0 ||
			clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.TrimSuffix(p, "/") != clean {
			return fmt.Errorf("match: path %q: a clean relative prefix of at most %d characters", clip(p), MaxPathLength)
		}
		if seen["p:"+p] {
			return fmt.Errorf("match: path %q is listed twice", clip(p))
		}
		seen["p:"+p] = true
	}
	return nil
}

func isControl(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

// Lesson is what a lesson record holds that this package scores and quotes.
type Lesson struct {
	UID               string    `yaml:"uid"`
	Type              string    `yaml:"type"`
	Title             string    `yaml:"title"`
	Summary           string    `yaml:"summary"`
	Kind              string    `yaml:"kind"`
	Status            string    `yaml:"status"`
	Systems           []string  `yaml:"systems"`
	Match             *MatchDef `yaml:"match"`
	Symptom           string    `yaml:"-"`
	PreventiveControl string    `yaml:"-"`
	Method            string    `yaml:"-"`
}

// Runbook is what a runbook record holds that this package scores and quotes.
type Runbook struct {
	UID          string    `yaml:"uid"`
	Type         string    `yaml:"type"`
	Title        string    `yaml:"title"`
	Summary      string    `yaml:"summary"`
	Systems      []string  `yaml:"systems"`
	Match        *MatchDef `yaml:"match"`
	SupersededBy string    `yaml:"superseded_by"`
	Purpose      string    `yaml:"-"`
}

// inactiveLesson are the lesson statuses of a record that has graduated or been replaced.
var inactiveLesson = map[string]bool{"retired": true, "incorporated": true, "superseded": true}

// Hit is one matched entry: its uid, its score and why it scored.
type Hit struct {
	UID   string
	Score int
	Why   []string
}

type entry struct {
	uid         string
	keywords    []string
	paths       []string
	spans       []string
	tags        map[string]bool
	titleTokens map[string]bool
}

// Index is the loaded registers: only the active entries that declare a match.
type Index struct {
	lessons   []entry
	runbooks  []entry
	lessonOf  map[string]Lesson
	runbookOf map[string]Runbook
	nLessons  int // records read, matchable or not
	nRunbooks int
	skipped   int // records without a match, or inactive
}

// LoadIndex reads the lessons register directory and, when runbooksDir is not "", the runbooks
// register directory.
func LoadIndex(lessonsDir, runbooksDir string) (*Index, error) {
	ix := &Index{lessonOf: map[string]Lesson{}, runbookOf: map[string]Runbook{}}
	if err := ix.readDir(lessonsDir, "lessons"); err != nil {
		return nil, err
	}
	if runbooksDir != "" {
		if err := ix.readDir(runbooksDir, "runbooks"); err != nil {
			return nil, err
		}
	}
	return ix, nil
}

// LoadConfigured is the controller's loader for lessons_path / runbooks_path (config.Registers).
// Both empty: no index (nil, nil). A path that is set but unreadable is an error, and so is a
// runbooks_path without a lessons_path, and a register that holds no record (a wrong path, an
// empty directory): every prompt would silently lose its register context.
func LoadConfigured(lessonsDir, runbooksDir string) (*Index, error) {
	if lessonsDir == "" {
		if runbooksDir != "" {
			return nil, fmt.Errorf("runbooks_path %s is set but lessons_path is empty", runbooksDir)
		}
		return nil, nil
	}
	ix, err := LoadIndex(lessonsDir, runbooksDir)
	if err != nil {
		return nil, err
	}
	if ix.nLessons == 0 {
		return nil, fmt.Errorf("lessons register %s holds no record", lessonsDir)
	}
	if runbooksDir != "" && ix.nRunbooks == 0 {
		return nil, fmt.Errorf("runbooks register %s holds no record", runbooksDir)
	}
	return ix, nil
}

func (ix *Index) readDir(dir, kind string) error {
	files, err := recordFiles(dir)
	if err != nil {
		return fmt.Errorf("%s register: %w", kind, err)
	}
	for _, name := range files {
		path := filepath.Join(dir, name)
		data, err := readBounded(path, maxRecordBytes)
		if err != nil {
			return fmt.Errorf("%s register: %w", kind, err)
		}
		uid := strings.TrimSuffix(name, ".md")
		evs, err := transitions(filepath.Join(dir, uid+".events"))
		if err != nil {
			return fmt.Errorf("%s register: %s: %w", kind, name, err)
		}
		if err := ix.add(data, uid, kind, evs); err != nil {
			return fmt.Errorf("%s register: %s: %w", kind, path, err)
		}
	}
	return nil
}

func (ix *Index) add(data []byte, uid, kind string, evs []transition) error {
	rec, err := readRecord(data, kind)
	if err != nil {
		return err
	}
	// apply the transitions to the front matter as the register does: `set` replaces fields, a
	// lesson's status becomes `to`; each must start where the last one ended
	front := rec.front
	if err := applyTransitions(front, kind, evs); err != nil {
		return err
	}
	if kind == "lessons" {
		var l Lesson
		if err := front.Decode(&l); err != nil {
			return err
		}
		if err := checkIdentity(l.UID, l.Type, uid, "lesson"); err != nil {
			return err
		}
		l.Symptom, l.PreventiveControl, l.Method = rec.fields["symptom"], rec.fields["preventive_control"], rec.fields["method"]
		ix.nLessons++
		if l.Match != nil {
			if err := l.Match.check(); err != nil {
				return err
			}
		}
		if l.Match == nil || inactiveLesson[strings.TrimSpace(l.Status)] {
			ix.skipped++
			return nil
		}
		ix.lessonOf[uid] = l
		ix.lessons = append(ix.lessons, newEntry(uid, l.Match, l.Systems, l.Title, l.Title+" "+l.Symptom))
		return nil
	}
	var r Runbook
	if err := front.Decode(&r); err != nil {
		return err
	}
	if err := checkIdentity(r.UID, r.Type, uid, "runbook"); err != nil {
		return err
	}
	r.Purpose = rec.fields["purpose"]
	ix.nRunbooks++
	if r.Match != nil {
		if err := r.Match.check(); err != nil {
			return err
		}
	}
	if r.Match == nil || r.SupersededBy != "" {
		ix.skipped++
		return nil
	}
	ix.runbookOf[uid] = r
	ix.runbooks = append(ix.runbooks, newEntry(uid, r.Match, r.Systems, r.Title, r.Title+" "+r.Summary+" "+r.Purpose))
	return nil
}

func checkIdentity(got, typ, file, want string) error {
	if got != file {
		return fmt.Errorf("uid %q is not the file's name", clip(got))
	}
	if typ != want {
		return fmt.Errorf("type %q: want %s", clip(typ), want)
	}
	return nil
}

func applyTransitions(front *yaml.Node, kind string, evs []transition) error {
	for _, t := range evs {
		cur := scalar(front, "status")
		if kind == "runbooks" {
			cur = "active"
			if scalar(front, "superseded_by") != "" {
				cur = "superseded"
			}
		}
		if t.From != cur {
			return fmt.Errorf("transition from %q, but the record is %q at that point", t.From, cur)
		}
		keys := make([]string, 0, len(t.Set))
		for k := range t.Set {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var v yaml.Node
			if err := v.Encode(t.Set[k]); err != nil {
				return err
			}
			setKey(front, k, &v)
		}
		if kind == "lessons" {
			setKey(front, "status", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t.To})
		}
	}
	return nil
}

func scalar(n *yaml.Node, key string) string {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key && n.Content[i+1].Kind == yaml.ScalarNode {
			return n.Content[i+1].Value
		}
	}
	return ""
}

func setKey(n *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = v
			return
		}
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

func newEntry(uid string, m *MatchDef, systems []string, title, spanText string) entry {
	e := entry{uid: uid, paths: slices.Clone(m.Paths), spans: spans(spanText), tags: map[string]bool{}, titleTokens: titleTokens(title)}
	for _, k := range m.Keywords {
		e.keywords = append(e.keywords, strings.ToLower(k))
	}
	for _, s := range systems {
		e.tags[strings.ToLower(s)] = true
	}
	return e
}

// pathScore scores each of the entry's own paths once when it prefixes one of the paths the job
// names (never when it merely occurs inside one: vendor/roles/proxy/ is not under roles/proxy/).
func pathScore(paths, entryPaths []string) (int, []string) {
	score := 0
	var why []string
	for _, p := range entryPaths {
		for _, x := range paths {
			if strings.HasPrefix(x, p) {
				score += wPath
				why = append(why, "path:"+p)
				break
			}
		}
	}
	return score, why
}

// score is one entry's score against a task, and why; Why's order is fixed for one input.
func (e entry) score(textL string, toks map[string]bool, paths []string) (int, []string) {
	score := 0
	var why []string
	for _, kw := range e.keywords {
		if containsWord(textL, kw) {
			score += wKeyword
			why = append(why, "keyword:"+kw)
		}
	}
	ps, pwhy := pathScore(paths, e.paths)
	score += ps
	why = append(why, pwhy...)
	if score == 0 {
		// the record's match decides whether it applies; the other signals only rank
		return 0, nil
	}
	for _, sp := range e.spans {
		if strings.Contains(textL, sp) {
			score += wSpan
			why = append(why, "span:"+sp)
		}
	}
	var hits []string
	for t := range e.tags {
		if toks[t] {
			hits = append(hits, "tag:"+t)
		}
	}
	sort.Strings(hits)
	score += wTag * len(hits)
	why = append(why, hits...)
	hits = hits[:0]
	for t := range e.titleTokens {
		if toks[t] {
			hits = append(hits, "title:"+t)
		}
	}
	sort.Strings(hits)
	score += wToken * len(hits)
	why = append(why, hits...)
	return score, why
}

// containsWord reports whether kw occurs in text as whole words: not inside a longer word ("disk
// full" is not in "disk fuller", "cache" is not in "cachet").
func containsWord(text, kw string) bool {
	for from := 0; ; {
		i := strings.Index(text[from:], kw)
		if i < 0 {
			return false
		}
		start, end := from+i, from+i+len(kw)
		before, _ := utf8.DecodeLastRuneInString(text[:start])
		after, _ := utf8.DecodeRuneInString(text[end:])
		if (start == 0 || !isWordRune(before)) && (end == len(text) || !isWordRune(after)) {
			return true
		}
		from = start + 1
	}
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }

func best(entries []entry, text string, paths []string) []Hit {
	textL := strings.ToLower(text)
	toks := tokens(textL)
	var out []Hit
	for _, e := range entries {
		if s, why := e.score(textL, toks, paths); s >= minScore {
			out = append(out, Hit{UID: e.uid, Score: s, Why: why})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].UID < out[j].UID
	})
	if len(out) > topK {
		out = out[:topK]
	}
	return out
}

// MatchLessons returns the best lessons for a task and the paths it names.
func (ix *Index) MatchLessons(text string, paths []string) []Hit {
	return best(ix.lessons, text, paths)
}

// MatchRunbooks returns the best runbooks for a task and the paths it names.
func (ix *Index) MatchRunbooks(text string, paths []string) []Hit {
	return best(ix.runbooks, text, paths)
}

// LessonByUID returns a matchable lesson by its uid.
func (ix *Index) LessonByUID(uid string) (Lesson, bool) { l, ok := ix.lessonOf[uid]; return l, ok }

// RunbookByUID returns a matchable runbook by its uid.
func (ix *Index) RunbookByUID(uid string) (Runbook, bool) { r, ok := ix.runbookOf[uid]; return r, ok }

// Counts reports the records read and how many of them can never be matched (no match, or
// inactive), so the controller can log what the registers hold at load.
func (ix *Index) Counts() (lessons, runbooks, unmatchable int) {
	return ix.nLessons, ix.nRunbooks, ix.skipped
}

// clip bounds an untrusted string quoted in an error.
func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
