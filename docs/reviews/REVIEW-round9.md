# Review, round 9: the CSAF advisory cap

Seven personas, two rounds of cross-examination, on branch `csaf-advisory-cap` at
`378a989` with a clean working tree.

## Verdict

The project is on a sound footing: the naming boundary is the best-engineered
thing in the repository (the `_NAME_OK_PATHS` allowlist is explicit, short, fails
closed, and has already refused a publication rather than leak 37 names), the
voice is disciplined, and round 9 correctly identified that a cap nobody could
see was a cap nobody had disclosed. What round 9 did not do is finish the
thought: the denominator it computed lives only inside a sentence, the "newest"
guarantee it published has no test, the providers it named are read through a
guard that cannot see one disappear, and roughly half of what it added to
`/status` is a second rendering of something already on the same page.

Two things are wrong for readers and consumers today, independent of round 9,
and they are the first items below: the front page promises a removal route that
`.well-known/security.txt` on the same origin denies, and typing a CVE ID into
the search box on the front page can return "Nothing matches" for an ID that is
in the published data.

---

## FIX

### F1. The front page promises a correction route the site does not operate
**blocker. Fairness, Design, Data Consumer, Subtraction.**
`templates/_panel.html:188-194` still renders "the entire point of having a
correction route", "someone asking to be delisted" and "rows a CNA had
contested". `rbp/site.py:1503` writes `.well-known/security.txt` saying "This
site does not operate a removal channel for listed CVE IDs", and no `mailto:`
appears on any built page. `rbp/site.py:1368` repeats the promise in
`data/archive.json`'s `note`. `templates/method.html:385-387` still says the
User-Agent "gives any publisher a route to complain", a fourth surface the
retirement missed and the one aimed at the reader most likely to need it.

Do: rewrite the panel paragraph to state the mechanical property only (a
withheld row leaves every artefact including the archive, so a dated figure can
go down), same for the `archive.json` note, and cut "a route to complain" from
`/method`. Publish one honest sentence saying the site takes no removal requests
and why, beside the 7-day buffer that is the actual embargo mitigation, because
deleting the promise without replacing it leaves the reader with no route and no
acknowledgement that there is none. Pin the strings `correction route` and
`delisted` as absent from every built page, in the same posture as the existing
retired-withhold absence tests. While in that file, delete the second of the two
`<h2>The data</h2>` elements on `templates/_panel.html:168`, which renders twice
on the launched front page.

### F2. Searching a CVE ID on the front page can answer "Nothing matches" for an ID that is on the list
**blocker. Practitioner, Data Consumer, Design, Fairness.**
`templates/list.html:540` applies `DEFAULT_AGE = "90-"` when `location.search` is
empty; `writeUrl` (`:531`) serialises every non-empty control including the one
nobody chose; `els.q` writes on every keystroke (`:556`). Measured on a launched
build: landing on `/` and searching `CVE-2025-0094`, which is published at 572
days, produced `?q=CVE-2025-0094&age=90-` and the list read "Nothing matches".
The offered remedy makes it worse: Clear Filters (`:481`) blanks every control
including `q`, and the advice line says "Try a different term", which is exactly
wrong for a reader holding one ID. The `#viewnote` disclosure of the 90-day
default is suppressed by the first keystroke (`:540-546`).

Do: do not apply `DEFAULT_AGE` at all when `q` is non-empty, and do not serialise
`age` unless the reader set it (URL-supplied or a `change` event; the legacy
`?minage=` migration path at `:550-554` has to set that flag too, or old shared
links stop migrating). Rewrite the empty state: when `q` looks like a CVE ID, say
the list covers only configured feeds and that an absence here is not a statement
that the ID is published, and point at the state check (F3) instead of "try a
different term". Make Clear Filters preserve `q` and relabel it "Search all
rows". `age=any` written by Show All still survives, so a deliberate widening is
unaffected.

### F3. Rows whose only evidence is Samsung have no link a reader can open
**high. Practitioner, Design, Fairness, Data Consumer, Pipeline, Staff Python (six independent filings).**
`report._u` (`rbp/report.py:53-90`) dispatches on exact slug and has branches for
eleven of the thirteen `feeds.ADAPTERS`; `samsung` is missing from the function
and from the precedence tuple at `:92`. 65 of 1,691 rows on the production
2026-08-27 snapshot are samsung-only with `source_urls == {}`, 63 of them inside
the default view, rendering as a bare CVE ID, the string "Samsung SMR Jun 2026",
and a dead chip.

Do: add the `samsung` branch to `_u` and to the precedence tuple, built from the
`SMR-<Mon>-<Year>` already in `refs` against
`https://security.samsungmobile.com/securityUpdate.smsb`. Add the completeness
guard that mirrors `tests/test_pipeline.py:409` (which already pins that every
`feeds.ADAPTERS` key appears in `clock._ORIGIN_KIND`): assert every adapter is
either handled by `_u` or listed in an explicit "publishes no per-ID page" set,
so a fourteenth adapter cannot ship linkless rows silently. Add one anchor per
row in the detail pane pointing at
`https://cveawg.mitre.org/api/cve-id/<id>`, labelled as the state check rather
than as the advisory, so the reader can confirm RESERVED themselves; today that
endpoint appears once on `/method` as a hardcoded example. Do **not** add an
`arch` branch: arch publishes zero rows and zero only-source rows.

This pairs with D1. Land the branch and the deletion together so a row never
loses and gains a link in separate releases.

### F4. The CSV's evidence column is a Python `repr` and its booleans are `True`/`False`
**high. Practitioner, Data Consumer, Fairness, Staff Python, Design, Subtraction.**
`rbp/site.py:1295-1298` writes through `csv.DictWriter` with no value coercion,
so `source_urls` reaches the file as `{'alas': 'https://...', 'debian': '...'}`
and `json.loads` raises on row 1. Six to nine columns render Python booleans.
`data/rbp.csv.meta.json` declares `source_urls` type `object`, calls it "This is
the evidence", and says nothing about how an object is spelled in a cell.

Do: `json.dumps` for dict values and lowercase `true`/`false` for booleans, in
one place in the CSV projection, and state the CSV encoding of each non-string
type in `rbp.csv.meta.json` beside its declared type. Land this on its own and
before D2: correcting a value no parser can read breaks no consumer that
currently works, and it is the precondition for removing `advisory_url`. Do this
after D3 so eleven of the boolean columns are gone before the rest are re-encoded.

### F5. A run that read half the configured feeds publishes as a healthy run, and a feed that disappears is invisible to the shrink guard
**blocker. Data Consumer, Pipeline, Staff Python.**
`compare_magnitudes` (`rbp/feeds.py:239`) iterates
`sorted((current or {}).items())`, so a feed or part present last run and absent
this run is never handed to `_cmp`. Measured against the two snapshots on disk:
13 feeds and 1,691 rows on 2026-08-27, 6 feeds and 149 rows on 2026-08-28, seven
feeds carrying 65,994 ids gone, and `feeds.compare_magnitudes(prev, cur)` returns
`[]` with `degraded: false`, `shrunk: []`, `degraded_reasons: []`. The only
distinguishing key in the whole envelope is `profile: "custom"`, which appears in
no FIELDS entry, no CSV column and on no page. `resolved.json` correctly claims
28 closures, so the other 1,514 disappearances read as unexplained. This is the
project's named worst failure mode arriving in the one shape that clears every
guard and every published caveat at once.

Do: walk `(set(previous) & set(requested)) | set(current)` rather than `current`
alone, so a feed or part that vanished is a finding rather than an absence, and
intersect with the requested set so a deliberately narrowed run does not report
every unrequested feed as lost (`feed_detail` does not carry `requested` into
`compare_magnitudes` today; it needs to). Publish `feeds_requested` and
`feeds_read` in the envelope beside `profile`, document `profile` in FIELDS with
the explicit statement that a non-standard profile means a lower floor than the
archive's other entries, and make a requested set smaller than the profile's a
`degraded_reasons` entry. The same change should record what the shrink guard
compared against (a snapshot date, or null), which folds in the separately filed
"cannot be checked reads as checked and fine" gap and matches what
`freshness_unmeasurable` already does two lines below.

### F6. CSAF VEX statements are ingested as advisories and start the 72-hour clock
**high, arguably blocker. Fairness, Staff Python, Pipeline.**
`feed_csaf._fetch` (`rbp/feeds.py:2007-2027`) reads `document.publisher` and
`document.tracking`, then accepts every in-scope `vulnerabilities[].cve`. It
never reads `document.category` and never reads `product_status`; `grep` for
`vex|VEX|not_affected|product_status` across `rbp/`, `FEEDS.md` and `NEXT.md`
returns nothing. `clock.py:247` maps `csaf` to "advisory", so a statement that a
product is `known_not_affected` yields a row with `clock_origin: advisory`, an
advisory date, `rule 4.5.1.6 SHOULD` and `past_expectation: true`.
`/method:88-99` builds the site's most careful argument on exactly this
distinction and applies it to four tracker feeds and not to the feed where the
volume is largest. Separately measured live: SUSE lists two directory
distributions, and the `csaf-vex` one carries 60,501 in-scope per-CVE documents
against 14,601 advisories, taking a mean 77 percent of that provider's 120-slot
budget, with zero real SUSE advisories in the newest 120 on 26 of 120 simulated
six-hourly ticks.

Do two things, in this order. First, filter at the parser where the field is
declared: accept a document only when `document.category` is an advisory category,
and skip a vulnerability whose `product_status` contains only
`known_not_affected`. Do not sniff filenames for `cve-*.json`; the same class of
assumption is already memorialised in `_csaf_directory_entries`'s docstring as
having cost 14,486 dropped advisories. Second, allocate and record the cap per
directory rather than once over the union, so one provider's two listings do not
compete and `read` stops swinging 0 to 888 by document mix. Record the resulting
row-count change in `NEXT.md`, because it lowers a published count and the shrink
guard should be told why.

Note for the record: this is not a round 9 regression. `git show fe8f453^`
confirms the old code applied a per-directory cap and then the same global cut,
which is arithmetically identical. Round 9 changed the reported denominator, not
one fetched URL.

### F7. "no advisories in scope: <vendor>" is published about providers we failed to read or starved of budget
**high. Fairness, Pipeline, Design, Data Consumer.**
`rbp/feeds.py:2110-2111` is a plain `if read == 0: empty.append(host)` reached
after the status branch above may already have recorded the same host as CAPPED
or unreachable, so one run can name a vendor twice in one sentence. `read == 0`
is also what a provider produces when every listing fetch failed (`_get_text` at
`:518` has no retry where `_get` has three) and when its whole cap was spent on
out-of-scope documents. The 2026-08-27 production snapshot publishes "no
advisories in scope: www.huawei.com, www.innomic.com, www.open-xchange.com,
www.sick.com, www.suse.com" while `rbp/feeds.py:1682-1695` records in the same
file that Huawei serves 121 directories that all answer 401 and has 444 published
CVEs in the window, and while round 9 measured SUSE at 83,091 listed advisories.

Do: make the branch an `elif` (one keyword), change the string to "nothing
readable in scope", which is the claim the code can support today, and give
`_get_text` the same retry as `_get`. Most of this becomes moot once D5 removes
the vendor-name lists from the parent string entirely; do the `elif` and the
wording now regardless, because the sentence is on the launched page. Split the
`_csaf_fixture` in `tests/test_degraded.py:864` so "read it, it was empty" and
"could not read it" are two fixtures rather than one `[]` serving both: today no
assertion in that file can tell them apart, which is why the conflation survived.

### F8. The cap's "newest" guarantee has no test, and the whole suite passes if it keeps the oldest 120
**high. Staff Python, Pipeline, Fairness, Data Consumer, Design.**
The cut is `entries.sort(reverse=True)` (`rbp/feeds.py:1976`) then
`entries[:cap_per_provider]` (`:2000`). Three panellists independently mutated
line 1976 to `entries.sort()` and ran the offline suite: 946 passed, 9 skipped,
zero failures. The site would publish "read the newest 120 of 83,091 advisories"
while reading the oldest, on a page and in `limitations`. The five tests that pin
"newest" drive `_csaf_directory_entries` with a `cap=` argument no production
caller passes, and `tests/test_degraded.py`'s `_csaf_fixture` returns the same
one-CVE document for every advisory URL, so which 120 were chosen is unobservable
to any assertion.

Do: build a provider whose listing spans distinguishable dates, drive `feed_csaf`
end to end with `cap_per_provider=3`, and assert on the argument list `_get` was
actually asked for. That is the only formulation the fake cannot satisfy by
accident, and it is the same test that would catch the per-directory allocation
change in F6. Land it before D9 deletes the dead parameter, not after, so there
is no window with no pin at either site.

### F9. Every `.chip-*` status modifier loses to the list-page link pill
**high. Design, Data Consumer, Practitioner, Subtraction.**
`static/css/rbp.css:984` is `a.chip,span.chip{...border:1px solid
var(--rbp-link);color:var(--rbp-link)}` at specificity (0,1,1), 878 lines after
`.chip-ok`, `.chip-unmeasured`, `.chip-must`, `.chip-should`, `.chip-late`,
`.chip-corrob`, `.chip-none` at (0,1,0). Measured with `getComputedStyle` in
Chrome on the built `/status`: in light theme all seven variants return
`rgb(10, 88, 202)` for both colour and border and `border-radius: 999px`;
`.chip-unmeasured`'s dashed border computes as solid in both themes. Contrast
still passes 4.5 on every variant and every chip carries its word, so nothing
false is published, but the site's certainty vocabulary does not render.
`tests/test_a11y.py` reads declared values out of the CSS text, so it is green
while none of those colours is on screen.

Do: rename the list-page evidence pill to its own class in `chips()` and at
`rbp.css:984` so `.chip` means one component again, carrying `.nolink` with it
(`span.chip.nolink` at (0,2,1) currently survives the collision, and the honest
dashed no-link treatment must not regress). Delete the superseded
`a.src, span.src, span.src-nolink` block at `rbp.css:742-756`, which no template
emits. Do not add a render-time colour assertion: the rename restores
`test_a11y.py`'s validity by construction.

### F10. `table.table-sm` crushes instead of scrolling, on `/status` and `/method`
**high. Design (two independent measurements), Subtraction.**
`rbp.css:678-686` sets `display:block; overflow-x:auto` plus
`overflow-wrap: anywhere` on the cells below 768px, and `anywhere` reduces
min-content width so the block always fits and therefore never scrolls. Measured
at 320px on a launched build: all four `table-sm` elements across `/status` and
`/method` report `scrollWidth === clientWidth`, the feed table is 5,761px tall,
the `IDs read` header renders vertically at 26px by 235px, and the cell holding
`csaf:csaf.data.security.nozominetworks.com` is 53px by 474px. Round 9's new rule
at `rbp.css:227` extends the crush above the breakpoint. Document overflow is 0,
which is why the sweep stays green: the reflow pass was bought by destroying
legibility. `tests/render/test_layout.py:69-93` excludes these tables on the
recorded rationale that they "are DESIGNED to scroll inside their own box",
which is false on four of four instances.

Do: put `table.table-sm` inside the bounded `overflow-x: auto` region
`method.html:255` already uses, delete `display:block`, both
`overflow-wrap: anywhere` cell rules and line 227, and widen
`test_no_row_hides_behind_a_nested_scrollbar_below_the_boundary` to cover
`table-sm` with the assertion that a table whose `scrollWidth` equals its
`clientWidth` is not a scroll container.

### F11. `vendor` and `ecosystem` are published, documented as the defender-facing fields, and reachable from no filter
**high. Practitioner.**
`templates/list.html:430` builds the search haystack from
`cve_id + package + description + sources`. `ecosystem` is populated on 415 rows
(PyPI 88, Go 88, Packagist 84, Maven 62, npm 39, Android 38, and the rest) and
`vendor` on 179. Driven live with `age=any`: typing "PyPI" returns 0 rows.
A reader concludes no PyPI packages are affected.

Do: add both to the haystack. One expression, no schema change, no new data. If a
structured control is ever built, `ecosystem` is the one to build (415 rows, a
small closed value set), not the CSAF provider (27 rows). See D4 on `vendor`:
searchability is the only thing that would earn that column its place, and it
does not earn it for `vendor`, whose five values restate `sources`.

### F12. "Capped" means both our own cut and a provider that refused us, under copy saying it is never the provider
**high. Design, Fairness.**
Three call sites write CAPPED to a provider sub-row: `rbp/feeds.py:1937-1938`
(`provider unreachable: {str(e)[:60]}`), `:2093`, and `:2095-2099` (the real cap).
`templates/status.html:255-261` tells the reader Capped is "a limit this site sets
rather than anything the provider did", and `:345` renders all three as one chip.
Cisco and CISA 403 on every run, so this is standing, not hypothetical. The
fixture that pins the sentence, `_capped_csaf` in `tests/test_status.py`, has
three parts and no unreachable one, so the test asserts the copy against a shape
production never emits alone.

Do: delete the clause "which is a limit this site sets rather than anything the
provider did". The paragraph is then true of every row it describes, the Note
column already says which flavour, and no status constant changes, which matters
because CAPPED rather than FAILED for an unreachable provider is a considered
choice with fifteen lines of reasoning at `feeds.py:2075-2090` and a permanent
degraded banner on the other side of it. Replace `str(e)[:60]` with a fixed
string and put the exception in the run log: a truncated urllib error beside a
company hostname reads as an accusation, and a 403 to an unattended crawler is
ordinary. Add a `provider unreachable` part to `_capped_csaf`. Wrap the paragraph
in a condition on whether anything on this run is actually capped; on the current
build it renders above a table where every row is OK.

### F13. Published envelopes describe the wrong payload, the wrong producer and an undeclared row shape
**high. Data Consumer, Practitioner, Subtraction, Staff Python.**
Three defects in `rbp/schema.py:envelope` and `rbp/site.py:_write_data`, all
corrections rather than additions:

- **Provenance.** `site.py:1352-1354` calls `envelope()` for each archive file, and
  `envelope()` calls `source_commit()` unconditionally, so both archive files are
  stamped with the build commit `378a989` while the snapshots they came from
  record `8e3479de` and `3b806a1b`. Pass `snap_sum["source_commit"]`,
  `source_dirty` and the snapshot's own `schema_version` through; the values are
  already loaded on the line above. This is the mechanism behind the FIELDS
  violations others measured: `public_date_origin` was added at `932d190` and no
  gather has run since `3b806a1`.
- **Payload.** `held-back.json` wraps 181 rows in `counts.total: 149`, and
  `resolved.json` wraps 28 rows whose key set is seven fields in a `columns` list
  of the 30 backlog fields plus the full row-level `caveats` block, including
  `days_public_is_a_floor_not_lateness` about a field the file does not contain.
  Derive the count from the rows handed in, and emit no `columns` or row-level
  `caveats` for kinds whose rows are not COLUMNS-shaped. `envelope()` already
  takes `kind`.
- **Undeclared keys.** `dates` and `disclosure_order` are present on 100 percent
  of rows in every published artefact and appear in neither COLUMNS nor FIELDS,
  and `NEXT.md` plans to change the meaning of `dates`. Declare them or strip them
  the way `RETIRED_ROW_FIELDS` are stripped, and derive the envelope's `columns`
  from the rows actually being written.

Do not add the per-row FIELDS-conformance validator to `assert_artefact`: it fails
closed on `snapshots/2026-08-20`'s 506 rows today, it would run over every archive
file forever, and most of what it would catch evaporates once D3 lands.

### F14. The corpus stage and the fetcher: three bespoke call sites, four unwanted handlers, one 1.8 GB allocation, zero tests
**high as a cluster. Staff Python (three findings), Data Consumer, Practitioner.**
All of it removes code.

- `rbp/cvelist.py:141` is
  `zipfile.ZipFile(io.BytesIO(outer.read(n)))`, three lines under a docstring
  saying "no full read into RAM". Measured against the real 583 MB baseline: peak
  RSS 2,161 MB, versus 382 MB for `zipfile.ZipFile(outer.open(n))`, which yields
  the identical 381,449-entry namelist. The `outer.read` also runs before any
  ceiling, so the outer container has no decompressed bound at all.
- `rbp/cvelist.py:54, 126, 240` make all three corpus network calls outside
  `feeds._OPENER`, with no `_url_ok`, no pinning, no redirect revalidation and no
  download ceiling; `:126` and `:240` take `browser_download_url` values out of a
  third-party JSON body. Route them through `feeds._get` and `feeds._stream_zip`,
  which already stream to disk under `MAX_ARCHIVE_BYTES`. Include
  `rbp/classify.py:185` so "network calls go through the shared helper" has no
  exceptions.
- `feeds.py:455` says "No http/file/ftp handlers are added". Enumerated on the
  live object, `_OPENER.handlers` contains `HTTPHandler`, `FTPHandler`,
  `FileHandler` and `DataHandler`, because `build_opener` skips a default only
  when a passed handler subclasses it. Build from
  `urllib.request.OpenerDirector()` and add only `_PinnedHTTPSHandler`,
  `_SafeRedirect` and `HTTPErrorProcessor`: four capabilities removed, the comment
  true by construction, and `_stream_zip`'s dependence on its single caller
  checking `_url_ok` first retired.
- **None of this is tested.** Three panellists demonstrated by mutation that the
  suite passes with `_url_ok`'s public-IP check deleted, with
  `_SafeRedirect.redirect_request`'s revalidation disabled, and with
  `_iter_records`' `MAX_ENTRY` check disabled. `grep` for `_url_ok` in `tests/`
  returns three lines, all monkeypatching it away. Add two assertions, not six:
  `_url_ok` rejecting a private-IP host, and `_SafeRedirect.redirect_request`
  stripping `Authorization` across hosts, both pure once `_public_ips` is stubbed.
  Add one synthetic double-zip whose inner entry exceeds `MAX_ENTRY`.

Recorded for the next reviewer: during round 2 a panellist's live `_url_ok`
mutation sat in the shared working tree, undetectable by anything except
`git status`. It has been reverted; `git status --porcelain` is clean at the time
of writing and `rbp/feeds.py:407` reads the committed line. Treat any diff
touching that function as unreviewable by the suite until the two tests exist.

### F15. Seventeen CSAF providers and every OSV ecosystem are outside the frozen-feed guard
**high. Pipeline.**
`gather` stamps `newest`, `oldest` and `dated_rows` on the top-level adapter key
only (`rbp/feeds.py:2413-2415`); no part is ever stamped, and the parts in
`snapshots/2026-08-28/summary.json` carry exactly
`['capped','detail','ok','rows','status','truncated']`. `stale_feeds` then refuses
to look: `rbp/feeds.py:307-308` is `if ':' in name: continue  # sub-fetch; the
parent carries it`, and the parent does not carry it, because a parent's `newest`
is the maximum across all seventeen providers and the freshest one satisfies it
for all of them. `compare_magnitudes` cannot see it either, by its own design: it
only asks whether a number went down, and a provider frozen on a stale listing
returns the same `read` for ever. The comment immediately above the code that
stamps these keys names this exact failure as the reason they exist, citing
mozilla at exactly 607 rows on six consecutive snapshots.

Do: collect `public_date` per provider in `feed_csaf` (`_fetch` already returns it)
and per ecosystem in `feed_osv`, pass them to `record_feed` the way `gather` does
per feed, and narrow `feeds.py:307-308` from "skip every part" to "skip a part
with no `dated_rows`", which routes an undated part into the `unmeasurable`
bucket that already exists and is already rendered. No new threshold, no new
concept, no new published key shape.

### F16. The GitHub watchlist controls neither the cache nor the published population
**medium. Pipeline, Data Consumer, Practitioner, Subtraction.**
`.github/workflows/deploy.yml:243-244` keys the poller-state cache on
`hashFiles('data/ghsa_repos.txt')`. The watchlist is at
`rbp/feed_data/ghsa_repos.txt` (`feeds.py:1119`), `data/` is gitignored and holds
no such file, so `hashFiles` returns the empty string and the key is a constant.
The comment directly above it describes a guard that has never fired. Separately,
`feeds.py:1385` emits rows from `entries` (the cached state) while the health line
at `:1403` reports `{polled} of {len(repos)}` over the watchlist, and
`_save_repo_state` prunes nothing, so a repo removed from the list would keep
contributing rows for ever. This feed is the sole source for 59 percent of
published rows.

Do: point both cache-key expressions at `rbp/feed_data/ghsa_repos.txt`, and prune
state keys not on the current list in `_save_repo_state`. The live state file
currently has 1,875 entries against 1,875 watchlist entries, zero stale, so
changing the emission set itself is unnecessary today and would drop rows on the
transition run; the prune on save is the cheap insurance.

### F17. `refs` is cut at 250 characters mid-token, and that is exactly where `sources` and `refs` disagree
**medium. Data Consumer.**
`rbp/classify.py:365` is `";".join(sorted(e["refs"]))[:250]`. Over the 1,691 rows
of the 2026-08-27 archive, exactly 3 rows hit the cap and exactly the same 3 rows
have a name in `sources` with no matching prefix in `refs`. The cut is applied
after the sort, so which reference is lost depends on the alphabetical order of
the feed slug, and `report._u` parses `refs` for four feeds, so a truncated ref
silently costs `source_urls` an entry too.

Do: delete the `[:250]`. Untruncated those three rows run about 300 characters in
a 154 KB artefact. State the resulting guarantee in FIELDS: every name in
`sources` has a reference in `refs`.

### F18. The source chip is read as attribution, and on the linkless rows it is the whole row
**high. Fairness.**
`templates/list.html:186-190` maps feed slugs to display names, and ten of them
(GitHub, Red Hat, Debian, Ubuntu, Microsoft, Mozilla, Samsung, Amazon Linux,
Alpine, Arch) are certified CNAs. On a samsung-only row the rendered content is a
bare CVE ID, "Samsung SMR Apr 2026", one chip reading Samsung, and 148 days past
the expectation, on a row whose own fields record `rule_basis: unattributed`,
`self_disclosed: false`, `owner_nameable: false`. Samsung SMR bulletins routinely
cite IDs reserved by Qualcomm, MediaTek, Unisoc and Google. The only sentence
pushing back is "leaves attribution to the Program", several hundred words away on
a different card, and neither `rbp.csv.meta.json` nor the JSON `caveats` block
says a feed name is not the reserving CNA.

Do: put one clause where the reader is, on the "Showing Up In" label or the
"Where It Surfaced, and When" detail heading, saying the name is the advisory that
cited the ID and not the CNA that reserved it. Mirror the sentence into
`rbp.csv.meta.json` under `sources` and into the JSON `caveats` block. F3's
samsung link is the other half: a linked chip lets a reader resolve the ambiguity
in one click.

### F19. FEEDS.md publishes its admissibility rule as unconditional, and twelve of seventeen CSAF providers never faced it
**medium. Fairness.**
`FEEDS.md:150-160` says "A candidate feed is merged only if it clears both".
`CSAF_PROVIDERS` is five URLs; the 2026-08-28 snapshot records seventeen parts, so
twelve advisory sources are in the corpus solely because one CERT-Bund
`aggregator.json` listed them, including the two largest by volume. `max_providers`
is 40 against 17 today, so the crawl set can more than double with no config
change and no notice. A vendor's first contact with `rbp-cves/1.0` can therefore be
a crawl it never invited, after which `/status` may name it under "no advisories
in scope" (F7) and `/method` tells it the User-Agent gives it a route to complain
(F1).

Do: one sentence in FEEDS.md stating the exception honestly, and lower
`max_providers` to the configured count plus a stated margin. This is distinct
from F5, which is about a provider that disappears; this is about one that
appears.

### F20. The CSAF cap's denominator exists only inside a formatted sentence
**medium. Data Consumer, Pipeline.**
`rbp/feeds.py:1999` computes `listed = len(entries)` and its only two readers are
f-strings (`:2095` and `:2097`); `record_feed` accepts only name, status, detail
and rows, so the part record keeps `rows=read` and the denominator survives as
English, republished as free text in `limitations` at `cli.py:633`.

Do: carry `advisories_listed` and `advisories_read` as integers on the part
record and derive both the `/status` Note and the `limitations` sentence from
them, deleting the `capped_reads` list at `:2095` that formats the same two
numbers a second time. Scope it to that: `_cmp` reads only `rows`, so the claim
that this feeds `compare_magnitudes` is false without new guard code, and the
completeness ratio is not worth a threshold until F6 fixes what the denominator
counts.

### F21. `classify` drops the product identifier the adapter already set, and `report` re-derives it from a string
**medium. Staff Python.**
`feed_ghsa_repos` emits `product` (owner/repo) on every row (`feeds.py:1400`),
`gather` carries it into the refs entry (`:2436`), and `classify._row`
(`classify.py:350-372`) reads `e.get("product","")` only to feed
`attributor.attribute()` and never puts it on the published row. `report._derive_meta`
then re-derives `package` by splitting the `refs` string with branches for four
feeds. This is the fourth instance in this review of one stage re-deriving or
discarding a field another stage owns. The merge in `gather` is also first-wins in
`--sources` order, so an ID seen by both osv and ghsa-repos would publish whichever
was listed first: harmless today because `product` reaches no column, and shipping
the moment it does.

Do: carry `product` onto the row in `classify._row` and have `report._derive_meta`
prefer it over re-parsing `refs`, keeping the ref-splitting branches only for feeds
whose adapters do not set it. Make the merge deterministic in the same change. Do
**not** populate the row label from it: see the dropped items, the owner/repo is
already in `description` and is already searchable, and duplicating it would print
the same string twice on 1,017 rows.

### F22. `summary.json` is a contract that says it is not one
**medium. Data Consumer, chair.**
Four of six published JSON artefacts carry `schema_version`; `summary.json` and
`precision.json` do not. It has 29 top-level keys, none of which appears in FIELDS,
COLUMNS or the sidecar, and its key set already drifts between the two snapshots on
disk (`single_origin` and `corroborated` on 2026-08-27, absent on 2026-08-28). It is
what `publish gate` reads, the source of every number on `/status`, and the only home
for `feeds.detail[].parts`, the structure eight findings in this round argued about,
including whether an absent `rows_published` means not-measured or zero.

**Chair addition.** It is also the only published artefact carrying per-CNA numbers:
`coverage.sightings` is a 539-entry map of CNA short name to published-CVE count
(Linux 7317, GitHub_M 11898, microsoft 3196, redhat 1005), plus `covered`,
`top_missed`, `off_roster` and `own_channel_cnas`. Every one of those is deliberately
allowlisted in `publish._NAME_OK_PATHS` with written justification, and the guard is
right that they attribute no row to anyone. But the file most likely to be mistaken
for a per-CNA scorecard is the one file with no schema, no version and no sentence
saying what its numbers count.

Do: stamp `SCHEMA_VERSION` on `summary.json` and write a short FIELDS-style table
for the dozen keys a consumer actually reads, `coverage.sightings` first, stating
explicitly that sightings are published CVEs in the corpus window and not
reserved-but-public rows. Add `"field_docs": "data/rbp.csv.meta.json"` to the
`rbp.json` envelope and rename that sidecar to something not named for the CSV, so
the documentation is reachable from the URL every page hands out. Correct
`schema.py:270-273`, which says FIELDS is "Published on /data"; there is no `/data`
page and no template for one. Do not build one: the sidecar is the better artefact
and only needs to be findable.

### F23. The row disclosure has no designed focus ring
**low. Design.**
`rbp.css:514` enumerates five `:focus-visible` selectors and omits `summary`, which
is focusable without a tabindex. Measured with real Tab presses (programmatic
`.focus()` does not match `:focus-visible` and will mislead anyone re-checking this):
the panel button gets `3px solid var(--rbp-link)` at 2px offset, and the next stop,
`SUMMARY.rowhead`, gets the UA ring, `auto 1px rgb(229,151,0)` at 0 offset. There are
100 of these per page and they are the only route to the per-feed dates and links.

Do: replace the five enumerated selectors with a bare `:focus-visible`. One selector
instead of five, no fall-through possible, and the higher-specificity `sortbtn`
override still wins. That makes this a removal. Skip tightening `_invisible()` in
`tests/render/test_focus.py`: once nothing can fall through, it buys nothing.

### F24. Record that no guard reads the built site
**low, documentation only. Practitioner, Pipeline, Fairness.**
`publish.check` reads only `.json/.csv/.jsonl/.md/.txt` from the staging tree
(`else: continue`), `gate` reads only `summary.json`, and
`tests/test_no_attribution.py` globs `out/data/**/*.json` with no HTML. Nothing
anywhere reads a rendered page. Do not close this with a token sweep over the built
HTML: run against the live 521-name roster it returns hits on `drupal`, `libreswan`,
`mozilla`, `zephyr`, `Gitea`, `CISA` and `Nozomi` across five pages, every one of
them deliberate content, and the allowlist mechanism that makes the JSON branch work
is expressed as JSON paths that HTML does not have. Write one paragraph in `NEXT.md`
saying the guard does not cover rendered pages, so nobody argues from a coverage it
does not have. If a guard is ever wanted there, it must be positional (no roster name
in an attribution position) rather than a token sweep.

---

## DELETE

### D1. `advisory_url`, the cve.org fallback, and the test that pins it
**high. Subtraction, Data Consumer, Practitioner, Design, Fairness, Pipeline, Staff Python (seven filings of one defect).**
`rbp/report.py:100-101` assigns `https://www.cve.org/CVERecord?id=<id>` when no feed
supplies a page. Twelve lines later the same function says cve.org "is deliberately
NOT a fallback here. For a RESERVED id it renders nothing, so a link to it is worse
than no link: it looks like evidence and disproves itself." The published contract
carries both claims: `rbp.csv.meta.json` says under `source_urls` that cve.org is
never used as a fallback and under `advisory_url` that it is "Always populated".
`grep -rn advisory_url templates/` returns nothing: no page reads the field, and a
row with no URL already renders the honest dashed non-link chip.

Delete: the fallback (`report.py:100-101`), the precedence loop (`:90-99`), the
`advisory_url` return value and its writer at `:330`, its FIELDS entry
(`schema.py:361`) and its place in the published field list (`:264`), the CSV
column, and the assertion at `tests/test_pipeline.py:385` that pins the fallback as
correct. Order: F4 (parseable CSV) and F3 (samsung branch) first, then this, inside
the SCHEMA_VERSION 4 bump. Recorded dissent: the Data Consumer refuted this on the
ground that `advisory_url` holds a real link on 1,626 of 1,691 rows and is the only
usable link column in the CSV today. That is true only while `source_urls` is a
Python `repr`; once F4 lands, a consumer picks their own link instead of one chosen
by a precedence tuple published nowhere.

### D2. The columns that cannot vary
**high. Data Consumer, Practitioner, Fairness, Subtraction, Design.**
Over the 1,691 rows of the 2026-08-27 archive: `state`, `rule`, `rule_strength`,
`rule_certainty`, `rule_basis`, `self_disclosed`, `owner_nameable`,
`veto_evaluated`, `clock_known`, `disclosure_order` and `state_verified_this_run`
are single-valued; `public_date_origin` is empty on 100 percent of rows;
`own_feed_date` and `earliest_other_date` appear nowhere outside `schema.py:249,
318, 322` and one test. That is 14 of 30 CSV columns carrying zero information. The
mechanism: `site.py:362` sets `r['owner'] = None` on the publish path and
`clock.disclosure_order` returns "unmeasurable" when owner is falsy, so five of
those columns are produced by a code path unreachable while `NAMING_ENABLED` is
False. FIELDS actively invites the mistake by documenting alternatives ("or
4.5.1.4", "'candidate'", "'inferred-owner'") that no code path can produce.

Delete outright: `own_feed_date` and `earliest_other_date` (written by nothing).
Delete: `past_expectation`, which on the published set is exactly identical to
`clock_origin == "advisory"` with zero exceptions across 1,691 rows, because
`DEFAULT_MIN_AGE_DAYS = 7` is already 2.3x the 72-hour expectation, and delete the
`/method:94-99` paragraph that argues from a retired "522 of 522" figure while the
live ratio fails the same standard.
Keep but re-document: `rule`, `rule_strength`, `rule_certainty`, `rule_basis`,
`self_disclosed`. Cutting them at schema 4 means schema 5 re-adds them the day
`NAMING_ENABLED` flips, which is two breaks for consumers instead of one. State per
field, the way `owner_nameable` already does at `schema.py:326-331`, that the value
is constant under v1 and why, and stop documenting unreachable alternatives.
The project already wrote the rule for this when it cut `owner`: "a column that is
present and always null invites a consumer to build against it and wait for it to
fill."

### D3. The `vendor` column, `_SRC_VENDOR` and its precedence loop
**medium. Subtraction.**
`report.py:47-51` sets `vendor` by walking a fixed list and taking a display name
for the first matching slug in `sources`, so it is a pure function of a column
published on the same row. It is non-empty on 179 of 1,691 rows, its entire value
set is five distro names, no template renders it, and it is not in the filter, so
the docstring claim that it exists "so a defender can filter by software" is the one
thing it cannot do. `_SRC_VENDOR` also carries an `arch` entry the loop never
consults. Delete the column, the map and the loop, in the same cull as D2. Judge
`ecosystem` separately: it is real feed data rather than a restatement, and F11
makes it searchable, which earns it.

### D4. Do not build per-provider source identity, and do not take SCHEMA_VERSION to 4 for it
**high. Subtraction, Pipeline, Staff Python, Design, Fairness, Data Consumer (six disciplines, one conclusion).**
`NEXT.md` records `csaf:<host>` in `sources`, `dates` and `source_urls` as a taken
decision with six mitigations budgeted. The panel found four more traps before a
line was written: `report._u` and its precedence loop dispatch on exact slug, so
every CSAF row would fall through to the cve.org fallback with an empty
`source_urls`; `classify.py:363`'s `feed_count = len(sources)` silently redefines the
only corroboration proxy left after `indep_sources` was retired;
`templates/list.html:428` matches on exact token, so every already-shared
`?src=csaf` link returns zero rows and `:275` loses the roll-up option entirely; and
`feeds.py:166`'s `if len(srcs) == 1: only[srcs[0]] += 1` takes csaf's Only-source
figure to zero on the exact column `/status` added to answer what disappears if a
feed does. `chips()` unions `sources` with `keys(source_urls)`, so the proposed
workaround of putting the host in `source_urls` instead renders two chips for one
advisory, against a stated design where the chip count is the evidence count.
`report.py:492-497` would publish `csaf 0` in `report.md` on a run where csaf carried
rows.

Measured payoff: 27 of 1,691 rows cite csaf at all, 22 csaf-only, across five
providers of seventeen with any rows. Twelve of the seventeen `?src=` values would
return zero. And the per-provider row count is not yet a stable quantity: SUSE's
contribution swings 0 to 888 across ticks by document mix, and one of the seventeen
is a 301 duplicate of another.

Delete the plan. Record it in `NEXT.md` beside the independent-origin count, the
per-CNA page, the changes feed and the removal channel. Keep only the cross-provider
`seen` dedupe, which needs no schema change and which `NEXT.md` measures as changing
one published row. If a reader needs the CSAF advisory, `source_urls['csaf']` already
holds it and `list.html` already renders it as "Open Advisory"; provider identity is
already recoverable from that URL's host and from the publisher name in `refs`. A
plan that has accumulated ten traps before implementation has a wrong cost estimate.

### D5. The vendor-name lists in the CSAF parent health string
**high. Subtraction, Fairness, Pipeline, Design.**
`_record_csaf_health` (`feeds.py:2142-2185`) takes five accumulator lists of vendor
hostnames, assembles them into one string truncated at six and eight names, and
publishes facts the parts records now carry per provider. The two renderings are on
the same page, they disagree, and only the string version is false: the parent says
"no advisories in scope: www.huawei.com, www.innomic.com" while those same hosts'
parts say "ok 0 | 0 ids in scope". The denominator is self-certifying:
`n = len(providers)` with numerator `n - len(unreachable)`, so a run always publishes
`n/n` and the current 17 counts one publisher twice.

Delete the five accumulator lists and the truncated assembly; reduce the parent
detail to counts (providers read, ids, how many unreachable, capped or empty). That
removes the false vendor claim, the self-certifying form, the widest cell on
`/status` (the cell that forced the `overflow-wrap` rule in F10), and the route by
which vendor names reach `limitations` through `health_summary`. Add one clause
somewhere in the fan-out paragraph saying provider figures overlap and do not sum to
the parent, and delete the instruction at `rbp.css:198-201` telling the reader to
"compare a provider's IDs-read against its parent's by looking straight up the
column": the sub-rows sum to 6,793 against a parent of 2,992.

### D6. `, {gained} new` from the provider detail strings
**high. Subtraction, Data Consumer, Practitioner, Design, Fairness, Pipeline.**
`feeds.py:2103-2106` states in its own comment why `rows=` uses `read` and not
`gained`: "it depends on the order providers are visited". The strings on the same
two `record_feed` calls publish `gained` anyway, and the published snapshot shows the
contradiction in adjacent rows: `sick.com` "114 ids in scope, 102 new" above
`www.sick.com` "114 ids in scope, 0 new", the same publisher, the same 114 IDs.
Delete the clause from `feeds.py:2097` and `:2102`; `gained` keeps its stderr line at
`:2039` and `read` stays.

### D7. The two always-unmeasurable cells on the provider sub-rows
**high. Design (two findings), Subtraction, Data Consumer, Fairness.**
`merge_contribution` writes `rows_published: None` deliberately, because writing 0
"would publish 'this provider accounts for no rows on this site', which is a claim
about the provider". The template renders that None as a bare `&mdash;`: 34 unlabelled
cells, directly under a paragraph ending "a feed can return tens of thousands of IDs
while accounting for none of the list". The available reading is "none". A screen
reader announces nothing at all, because the cell's entire content is one punctuation
character with no text alternative, so the legend option fixes nothing for that
reader. With D4 decided, "always unmeasurable" is the permanent state, not a
temporary one.

Delete the two cells from the sub-rows and let the note column span them. Keep the
`setdefault` in `merge_contribution`: the Data Consumer's refutation held, an explicit
null is what makes the shape uniform in `summary.json`, and the Jinja
missing-key footgun it guards has already cost one live bug. Delete the duplicate
template test (`test_an_unmeasured_provider_contribution_renders_as_a_dash_not_a_blank`
and `test_a_part_that_predates_the_contribution_keys_still_renders_a_dash` assert the
same branch on two shapes `.get()` collapses to one) and the explicit
`"rows_published": None` keys in `tests/_sitefixture.py` and `tests/test_status.py`.

### D8. The Standing limitations card on `/status`
**medium. Subtraction, Fairness, Practitioner, Staff Python, Data Consumer.**
`health_summary` builds `capped` over the flat `FEED_HEALTH` with no `":" not in k`
filter, while the very next line applies exactly that filter for `attempts`.
`cli.py:633` publishes it as `limitations` and `status.html:388-410` renders each
entry roughly a hundred lines below the same string in a Note cell. On 2026-08-27
its single entry is character-identical to the csaf parent's Note. The card's own
copy says "a warning that is always on is not a warning".

Delete the card. Keep `stats["limitations"]` and its envelope key, filtered to
top-level names the way `feeds.py:133` already filters for `attempts`: the Data
Consumer's amend held, a structured statement of standing limits is worth having in
JSON, and deleting a published key belongs in the schema bump rather than a template
edit. Keep one sentence from the card, the one that is not in the Note column: that a
paginated advisory API read to a fixed cap is observed over a much shorter window than
a tracker read in full, so counts from the two are not comparable. Move it into the
feed-table intro beside the Capped explanation.

### D9. The dead `cap` parameter on `_csaf_directory_entries`
**medium. Subtraction, Staff Python, Pipeline, Data Consumer, Practitioner.**
`feeds.py:1777` takes `cap=None`; the sole production caller at `:1962` passes
nothing. The docstring keeps it because "another caller" might want it and because
"the tests that pin its behaviour are pinning real behaviour", which is circular:
those tests are the only thing exercising it. Delete the parameter, the two
`if cap is not None` branches, the two docstring paragraphs at `:1790-1801`, and
`test_cap_is_respected`. **After F8**, not before: those tests are today the only
executable statement anywhere that a CSAF cap keeps the newest of anything. One
unresolved detail to settle in the same change: the `index.txt` branch returns
undated tuples and relied on `keep[-cap:]`, so with no cap the global
`sort(reverse=True)` now places every undated entry below every dated one, and an
index.txt-only directory would be cut first under a health line saying "read the
newest". No live provider is in that shape today.

### D10. The hardcoded `sick.com` provider
**medium. Subtraction, Fairness, Pipeline, Data Consumer, Design.**
`feeds.py:1675` hardcodes `https://sick.com/...` while the aggregator supplies
`www.sick.com`; `_expand_csaf_providers` dedupes on exact URL string, so both are
read. Cost: two rows on a public page with contradictory numbers, 120 duplicate
advisory fetches per run, a provider slot, and "17/17 providers" for sixteen
publishers. Delete the line. This also retires `NEXT.md`'s trap 5, host
canonicalisation, which would rename every parts key and give the shrink guard a
one-run blind spot across all seventeen providers. Recorded dissent: Fairness argued
for keeping the configured entry and skipping the aggregator's `www.` variant
instead, because deleting the deliberate config line moves a chosen provider onto
the unscored aggregator path. That is a fair point about F19's territory, but it is
an argument for reviewing the other twelve, not for keeping this one.

### D11. About a third of `rbp.css`
**medium. Design, Practitioner, Data Consumer, Subtraction.**
Twenty of 87 class selectors and all three attribute selectors are emitted by no
template and appear on no built page: `.lead-count`, `.lead-unit`, `.lead-sub`,
`.lead-plain`, `.bound-strip`, `.filters` and its seven children including its own
768px grid block, `.result-count`, `.qualifier`, `.histo*`, `.metric-base`,
`.redacted`, `.visually-quiet`, `.chart-export-btn`, `a.src`/`span.src`/
`span.src-nolink`, `td.desc`, `td.unattributed`, `.sortbtn`, and `data-sort`,
`aria-sort`, `data-label`. `class="rbp"` appears on zero of the seven built pages,
because its one emitter is behind `{% if grader.misses %}` and precision currently
grades nothing, so the entire `table.rbp` component including the sticky thead, the
SC 2.4.7 sortbtn focus rule and the `data-label` card layout is unreachable. Several
dead blocks carry long comments arguing about defects in pages the pivot deleted,
which read to a later reader as live constraints; the `.chip` collision in F9 was
hiding among them.

Delete the unreachable rules and their comments; move anything worth keeping to
`PLAN.md`. Either give `method.html`'s misses table `data-label` attributes or
convert it to `table-sm`. Do **not** add the proposed build-time selector-reachability
check: `templates/list.html` builds every row class from JS strings, so it would flag
the most load-bearing classes on the site as dead on its first run.

### D12. The dated measurement tables pasted into `feeds.py`
**low. Subtraction, Practitioner, Fairness, Data Consumer.**
`feeds.py:1977-1999` is 22 comment lines guarding two lines of code, including a
six-row measurement table that also appears verbatim in `NEXT.md` and in the commit
message, with the argument restated again at `:2067-2081` and `:2166-2172`. These are
one-day measurements against a cap of 120 and go stale the moment the cap or a
provider's volume moves. Cut to the two sentences that do not go stale (`listed` must
be taken before the slice because after it the number is gone; a flat cap is invisible
to a guard that only asks whether a number went down) and point at `NEXT.md` for the
figures.

---

## Dropped, with the reason

These were filed, defended, and lost. Recorded so they are not re-filed.

- **`defender-software-identity-exists-in-refs-and-is-never-published`, the row-label
  half.** Refuted on the facts: ghsa-repos rows do not render as "a bare CVE ID over
  prose". Their `description` already reads `microsoft/vscode repository advisory
  GHSA-...`, `list.html:411` renders it, and `matches()` already searches
  `description`, verified live for vscode, django, kubernetes and openssl. Populating
  `package` from the ref would print the same string twice on 1,017 rows. The
  priority argument inside it survived and became part of D4; the root-cause half
  became F21.
- **`pipeline-provider-names-on-public-pages`.** Withdrawn by its own author under
  cross-examination. Provider hostnames were already published pre-round-9 in
  `limitations`, `_NAME_OK_PATHS` allowlists `.feeds.` with written rationale, and
  deleting the parts table would remove the only surface where a provider going dark
  is visible. Its one durable point became F24.
- **Extending `publish check` over the built site tree.** Measured rather than
  asserted: the project's own `_roster_names_in_text` over the built pages returns
  hits on `drupal`, `libreswan`, `mozilla`, `zephyr`, `Gitea`, `CISA` and `Nozomi`,
  all deliberate content, and the JSON allowlist is expressed as paths HTML does not
  have. See F24 for what to do instead.
- **A per-row FIELDS-conformance validator in `assert_artefact`.** Would fail closed
  today on `snapshots/2026-08-20`'s 506 rows, would run over every archive file on
  every run for ever, and polices a field list D2 is about to shorten.
- **A build-time check that every CSS selector appears in the rendered tree.** Would
  flag every JS-built row class as dead on its first run.
- **A render-time assertion that two chip variants do not compute to the same colour.**
  The rename in F9 eliminates the class of bug; a second harness watching a bug you
  have structurally removed is the accretion this panel exists to stop.
- **An ADAPTERS-completeness guard that forces a `_u` branch for every adapter.**
  Taken in the weaker form only (F3): every adapter must be handled or explicitly
  listed as having no per-ID page. The strong form would force dead branches for
  feeds that publish nothing.
- **An `arch` branch in `report._u`.** Arch publishes zero rows and zero only-source
  rows; the branch would be dead on arrival, as the existing `_SRC_VENDOR['arch']`
  entry already is.
- **Making `advisory_url` nullable.** Superseded by deleting it (D1): a nullable field
  that no template reads and that duplicates `source_urls` wherever it is populated is
  a documented null semantics for nothing.
- **Minting an "Unreachable" chip status.** Superseded by deleting the false clause
  (F12). A new status constant reopens the FAILED-escalation question that
  `feeds.py:2075-2090` spends fifteen lines settling, and risks a permanent degraded
  banner for Cisco's standing 403.
- **A legend clause explaining the em-dash.** Superseded by deleting the cells (D7);
  it also does nothing for a screen-reader user, who never encounters the dash.
- **Canonicalising CSAF provider hosts.** Superseded by D10. Renaming every parts key
  blinds the shrink guard across all seventeen providers for a run, to fix one
  duplicated row that one config line creates.
- **Deleting the `setdefault` loop in `merge_contribution`.** Refuted: the explicit
  null is what makes `parts` uniform in a file with no schema, and the Jinja
  missing-key trap it guards has already produced one live defect. The test and
  fixture cleanups from that finding were kept (D7).
- **Replacing `/method`'s retired "522 of 522" figure with the live ratio.** Refuted:
  it would print the site's own indictment ("a claim asserted on every single row does
  no discriminating work") immediately above a live number showing the claim is
  asserted on every single row, with no answer. Delete the field and the paragraph
  instead (D2).
- **Holding samsung-only rows back until `_u` has a branch.** Withholding 4 percent of
  the list to avoid a missing link is a far larger lever than the bug.
- **"Give the non-link chip a visible reason."** Additive copy on the densest surface
  on the site. `span.chip.nolink` is already dashed and unlinked; the reason a reader
  wants is a link (F3), not an explanation of its absence.
- **A standalone `shrunk_compared_against` key.** Folded into F5, whose union walk
  fires on live data where the no-baseline case needs a first-ever run or an
  unreadable snapshot.
- **The claim that the cap denominator would feed `compare_magnitudes`.** Overclaimed:
  `_cmp` reads only `rows`. F20 is scoped to deriving the sentence from integers, with
  no guard.

---

## Balance

Surviving items: 24 under FIX, 12 under DELETE.

By net effect on the codebase and the published contract:

- **Removes: 21.** All twelve DELETE items, plus F1, F9, F10, F12, F14, F17, F21, F23
  and the deletions inside F8 and F20.
- **Neutral: 8.** F4, F5's iteration set, F7, F11, F13, F16, F2 and F22's rename.
- **Adds: 7.** F3 (one `_u` branch, one coverage assertion), F5's two envelope keys,
  F6's two parser conditions and per-directory bookkeeping, F15's three keys per part,
  F18's one clause in three places, F19's one sentence, F20's two integers, F22's
  version stamp and short table, F24's paragraph in `NEXT.md`.

Doing all of it leaves a smaller codebase, a shorter published contract, one fewer
link field, roughly seven fewer published columns, about a third less CSS, one fewer
card on `/status`, one fewer table column pair, and one planned schema break that does
not happen. The two largest single items on the whole list are deletions: D4 (do not
build provider identity) and D2 (the columns that cannot vary).

That is the right direction here. This site's product is a list and its links, and
almost everything that went wrong this round went wrong by publishing a second
rendering of something already published: a health string beside a parts table, a
limitations card beside a Note column, an `advisory_url` beside `source_urls`, a
`vendor` beside `sources`, a `past_expectation` beside `clock_origin`. The additions
that survived are almost all in one category, and it is the right one: measuring a
state the site currently reports as its own opposite (a vanished feed, a frozen
provider, a VEX statement read as an advisory, a linkless row).

## What the panel disagreed about most

**Whether `advisory_url` should be deleted or repaired.** Six panellists wanted the
field gone; the Data Consumer refuted, on the ground that it holds a working link on
96 percent of rows and is the only link column a CSV consumer can use today, because
`source_urls` is an unparseable Python `repr` in that file. Both are right, and the
disagreement is really about sequencing: the deletion is safe only after F4. This
matters beyond the field itself, because it is the one place where the panel's
subtractive instinct nearly removed something a consumer was actually using. The
lesson to carry: before deleting a published key, check what the surviving alternative
looks like in every format it ships in, not just in the one you were reading.

**Whether provider identity should ship at all.** Six disciplines converged on no, from
six directions, which is the strongest signal in the review. The dissenting shape was
not "ship it" but "ship it with mitigations", and the reason that lost is worth
recording: the mitigation count went from six to ten during cross-examination, on a
change whose measured payoff is a filter over 1.6 percent of rows. A plan whose trap
list grows faster than its implementation is a plan with a wrong cost estimate, and
the correct response to trap seven is not to write mitigation seven.

**Which snapshot anyone was measuring.** Findings were filed at "76 of 149 rows, 51
percent of everything published" and at "65 of 1,691 rows, 3.8 percent", for the same
defect, and both numbers were honestly obtained. `snapshots/2026-08-28` is a six-feed
dirty-tree dev run (`requested` has six entries, `source_dirty: True`, `source_commit`
three commits behind the round-9 work) and it is what a fresh build currently publishes
into `data/`. Several severities were argued off it, and at least one blocker
("over half the front page has no link") is false of the launched site.

**Chair addition, and the process fix that follows.** That confusion is itself a
finding. `python -m rbp.cli build` should refuse to write `data/` from a snapshot whose
summary records `source_dirty: true` or a non-standard `profile`, or stamp the built
pages visibly when it does. F5 makes the state visible in the artefact; this makes it
impossible to publish by accident. Until then, every measurement quoted in a review of
this repository should name the snapshot it came from, and this document does.
