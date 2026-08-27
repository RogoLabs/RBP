# Round 6: the front end, before the announcement

Written 2026-08-27. Every finding below was reproduced twice: once against a
clean local build of the 2026-08-27 snapshot pulled from `origin/data`, and once
against the live host. Where the two disagree the live host wins and the
difference is stated.

**Status, 2026-08-27. All three passes are done**, and so are the six
decisions. What remains is one item, H5's addressability half, recorded at the
bottom as a v2 conversation rather than a defect.

Passes 1 and 2 were **done**: every blocker except H5's
addressability half, every high item except H5, and M1 and M5. Plus D1 answered
and the age filter. **Pass 3 is open**: M2, M3, M4, M6, M7, M8, and the D-list
decisions. Completed items are marked inline rather than deleted, because the
reasoning is the record.

Pass 2 also turned up **three defects that were not in this review**, all found by
guards written for the items that were. They are recorded under "Found while
fixing" below.

---

## First, the thing to agree on

**The site is already launched.** `https://rbptracker.org/` serves the list right
now, `robots` reads `index, follow`, `/overview.html` 404s and the live run is
clean: `degraded: false`, gate 42 of 50 at 84.0%, 1,709 rows. `NEXT.md` records
the flip on 2026-08-26 at 18:00Z and it is accurate.

So what is happening next week is the **announcement**, not the deploy. That
changes the shape of the work: every defect below is already public, already
indexable, and already what a reader sees if someone links the site today. There
is no staging window left to fix things in privately. It also means the epoch
decision has passed (see D5).

---

## Blockers: fix before you announce

### B1. The link preview contradicts the page. FIXED 2026-08-27

`templates/base.html:32` publishes `summary.corroborated` in `og:description`
while `og_title` and the `<h1>` publish `summary.total`. Live right now, on every
page:

    og:title        "1,709 reserved CVE IDs are public and unpublished"
    og:description  "201 CVE IDs are in the state the CVE Program calls
                     Reserved but Public..."

Two adjacent lines of the same unfurl, differing by 8.5x. This is the single
most-travelled string on the site and the one thing a Slack or Teams paste
renders, which is exactly the reason the block was hardened in the first place.

It is drift, not an error of judgement. When that `og:description` was written
the front page also led with the corroborated subset, and publishing the more
defensible figure in the unfurl was the right call. The 2026-08-26 pivot moved
the `<h1>` to `summary.total` and left the unfurl behind.

The same stale premise was also asserted in `rbp/schema.py:332`, in the
`single_origin` field documentation that ships in `data/rbp.csv.meta.json`:
*"which is why the site's headline is the corroborated subset rather than the
total."*

**What landed.** Jerry's answer to D1 was to drop the calculation, not repoint the
tag, so the fix went deeper than the meta tag:

- `report._indep` and `report._ORIGIN` deleted. `_ORIGIN` was the mirror-collapsing
  map (OSV re-publishes GHSA, ALAS is a RHEL rebuild) and `_indep` its only reader,
  so the whole mechanism went rather than being left to feed nothing.
- `indep_sources` and `single_origin` removed from the published row schema;
  `counts.corroborated` and `counts.single_origin` from the envelope;
  `corroborated` from the archive index and from the build log.
- `SCHEMA_VERSION` 2 to 3, per that constant's own rule that any published key
  removal bumps it, so a positional reader of `rbp.csv` fails loudly instead of
  reading `refs` where it expected `indep_sources`.
- `schema.RETIRED_ROW_FIELDS` added and stripped in `site._normalise_legacy`,
  which is the single read path. Without this the change would have cleaned only
  future snapshots: `rbp.csv` is projected through `schema.COLUMNS` and would have
  dropped the fields for free, while `rbp.json` rows and every dated archive entry
  are republished from the snapshot on disk verbatim and would have kept shipping
  a v2 field at v3. One artefact projected and one not is how the last
  scrubber/guard drift happened.
- `og:description` now renders `summary.total | commafy`, and the launched-posture
  build shows **1,691 in the `<h1>`, `og:title` and `og:description`**.
- `feeds.py`'s Samsung docstring and `FEEDS.md`'s CSAF finding both referenced the
  corroborated headline and were corrected rather than left.

**The guard, and why the old one missed it.** Every existing test on that string
checked how the figure was *guarded*, not *which figure it was*, so all of them
passed while the two counts diverged. `test_the_unfurl_and_the_heading_carry_the_same_count`
now parses `base.html` and `list.html` and asserts the `<h1>`, `og:title` and
`og:description` render the same `summary` key. Mutation-tested: reintroducing the
old expression fails it, restoring the fix passes.

Not touched: the *attribution* corroboration tier (`inference.TIER_CORROBORATED`,
the `chip-corrob` on `/method`). It shares the word and is a different mechanism, the product map agreeing with block inference on an owner *name*, and it is
switched off by `NAMING_ENABLED` rather than removed.

### B2. The front page carries a dead link. FIXED 2026-08-27

`templates/_panel.html:183` links `data/schema.json`. Nothing writes that file.
Live: `https://rbptracker.org/data/schema.json` returns 404 and serves GitHub's
generic error page.

The schema *is* published, at `data/rbp.csv.meta.json` (`rbp/site.py:1254`), so
this is a wrong filename rather than a missing artefact.

**The guard for this exists and could not see it.** Both link checkers match only
`.html`:

    tests/test_end_to_end.py:455   re.findall(r'href="([^"#?:]+\.html)"', ...)
    tests/test_site.py:163         re.findall(r'href="([^"#?:]+\.html)"', ...)

Every `data/*.json` and `data/*.csv` link on the site is unchecked, and the one
dead link on the site is a `.json`. `tests/test_site.py:143`'s docstring says the
duplication between the two copies is the point; the blind spot is identical in
both, so duplicating it bought nothing here. Widening the pattern is a
three-character change and it should land with the fix.

### B3. There is no favicon. FIXED 2026-08-27

Live, both of these 404:

    /favicon.ico
    /apple-touch-icon.png

No page emits a `<link rel="icon">`. Every browser tab, bookmark and pinned tab
shows a generic placeholder, iOS "Add to Home Screen" gets a screenshot, and the
404 fires on the first visit from every browser. This is the cheapest credibility
signal on the list and the site currently declines it.

`rbp/site.py:1409` copies `static/` wholesale, so an SVG under `static/img/` ships
without any build change; the root `/favicon.ico` path needs one explicit copy.

### B4. No `og:image`, no Twitter/X card. FIXED 2026-08-27

Neither appears on any page. Every paste into Slack, Teams, X, LinkedIn or
Mastodon renders as text with no image. For a site whose entire purpose is to be
cited, the unfurl is the product, and right now it is the least designed surface
on it.

The count is the image. A generated card carrying the number, the phrase
"reserved, public, unpublished" and the snapshot date would do more for the
announcement than any page change below. It can be a static SVG-to-PNG written by
the build from `summary.total`, so it never goes stale.

### B5. On a phone the `<h1>` is a bare number. FIXED 2026-08-27

`static/css/rbp.css:793`:

    @media (max-width:640px){ .cmd-count span{display:none} }

That span holds "reserved, public, unpublished". `display:none` removes it from
the accessibility tree as well as the layout, so the mobile `<h1>` is literally
`1,709`, no unit, no subject. Confirmed at 375x812: the heading reads `1,709`
and nothing else.

The `<h1>` was made real and made the count deliberately, for good reasons
recorded in `templates/list.html:11-30`. On the viewport where most shared links
are opened, it says nothing. The unit needs to survive the breakpoint, wrapped
under the number rather than hidden.

### B6. The panel undercounts the site's own feeds. FIXED 2026-08-27

`templates/_panel.html:159`: *"Ten public advisory feeds are read every six
hours."* There are thirteen (`rbp/feeds.py:1591`, and `summary.feeds.requested`
lists all thirteen on `/method`). Live on the front page, inside the panel that
answers "What is this?".

The site understates its own coverage on its most-read explainer, and `/method`
one click away lists thirteen. Worth counting from the data rather than typing,
the way `/method` already does.

### B7. A stale or mistyped link lands on GitHub's 404. FIXED 2026-08-27

There is no `404.html`. Live, `/anything-else` serves *"Page not found · GitHub
Pages"* with GitHub branding, GitHub's documentation links, and no route back to
rbptracker.org. That is also where B2's dead link sends a reader from the front
page.

Twenty lines extending `base.html` fixes it, and it matters more after an
announcement than before one: announcements produce mistyped and truncated links.

---

## High: worth fixing in the same pass

### H1. `/` ships two `<main>` elements, both `id="main"`. FIXED 2026-08-27

`templates/list.html:47` opens `<main id="main">` inside `templates/base.html:84`'s
`<main id="main" class="container">`. A `main` cannot be a descendant of another
`main`, the id is duplicated, and there are two landmarks where a screen reader
expects one. Confirmed in the DOM on the live page. Only `/` is affected.

### H2. The panel emits an unmatched `</div>`. FIXED 2026-08-27

`templates/_panel.html:156` closes a `div` that was never opened. The built page
is 14 `<div>` against 15 `</div>`. Browsers discard it silently, so nothing looks
wrong, but the announcement is the moment someone runs a validator over the page
and posts the output.

### H3. Rows give no sign that they open. FIXED 2026-08-27

`static/css/rbp.css:740-742` sets `list-style:none` on the row `summary` and hides
`::-webkit-details-marker`, and nothing replaces either. `cursor:pointer` is the
only affordance and it needs a mouse already on the row.

Everything behind that interaction is the evidence: per-feed first-seen dates and
the "open advisory" links. On the primary page of a site built to be cited, the
citations are hidden behind an interaction a reader has no way to know exists.

### H4. `/method` and `/policy` unfurl as "RBP Tracker". FIXED 2026-08-27

Neither template overrides `og_title`, so both inherit the default from
`templates/base.html:30` while their `<title>` elements read "Method" and "The
policy". Those are the two pages you will most want to link in a launch thread,
and both preview under a name that does not describe them.

### H5. No CVE ID appears in `/`'s HTML, and there is no `<noscript>`

The built front page is 1.82 MB, of which 1.79 MB (98.4%) is the inline
`<script id="rows" type="application/json">` blob. Zero `CVE-` strings occur in
the markup. The server-side empty state only renders when `summary.total` is 0,
so with JavaScript off the page is a command bar, a hedge, and nothing.

It gzips to 126 KB and renders fine, so this is not a performance blocker. It is
a reach blocker, and it has two separate consequences worth deciding on
separately:

- **Nothing without a JS engine sees the list.** Reader modes, text browsers,
  archivers and non-rendering crawlers get an empty page. A `<noscript>` block
  linking `data/rbp.csv` costs four lines and closes the honesty gap.
- **No CVE ID is addressable.** There is no per-ID URL and no ID in any indexed
  document, so a search for a specific reserved CVE will never reach this site.
  For "a page you can point at" that is the largest gap in the design, and it is
  a v2 conversation, not a launch fix.

---

## Medium: polish, in rough priority order

**M1. The panel remembers where you left it. FIXED.** Reopening "What is this?" restores
the previous scroll position, measured at 2,627 px of a 3,528 px panel after one
read-through, which lands a second visitor at the end of a policy argument under a
button labelled "What is this?". `setPanel` (`templates/list.html:277`) should
reset `scrollTop` on open, and use `focus({preventScroll:true})` so the browser's
own focus scrolling cannot fight it.

**M2. `/about-this-count` is the only page whose cards stop mid-screen. FIXED.**
`.card-prose` (`static/css/rbp.css:830`) caps width at 78ch with no auto margin,
so at a 1,199 px container the cards end at 869 px with 330 px of void to the
right. The measure was the right fix for the half-empty card it replaced; it just
needs `margin-inline` so the result reads as composed rather than truncated.

**M3. The skip link shows. FIXED.** `static/css/style.css:1282` parks it at `top:-40px`
and it computes to 41.6 px tall, so 1.6 px of blue sits in the top-left corner of
every page. Visible in every screenshot in this review.

**M4. Five tables have no `<caption>` or `aria-label`**, three on `/method`, two
on `/status`. The `.tablewrap` on the misses table gets this right and is the
pattern to copy.

**M5. Repeated link text. FIXED.** The front page renders "OSV" 44 times and "open
advisory" many more, each to a different URL, with no per-row accessible name. A
screen reader's link list is unusable. `aria-label="OSV advisory for
CVE-2025-0094"` on the chip fixes it inside `rowHtml`.

**M6. The mobile menu does not close. FIXED.** No Escape handler, no outside-click
handler, no focus management, and five links occupy 470 px of an 812 px viewport.

**M7. About 7 KB of `static/css/style.css` styles components no template
renders**. 28% of its rule bodies, across `homepage-chart-*`, `stat-card`,
`chart-export-*`, `dropdown-menu`, `insight-card`, `quick-select-*`, `btn`. This
is the file whose duplicate unscoped rule produced the dark-theme AA failure
recorded in `NEXT.md`; every line of it that styles nothing is somewhere the next
one can hide.

**M8. Google Fonts is a render-blocking third-party request on every page. FIXED.** The
audience is CNAs and security teams, a meaningful share of them behind proxies
that block it. Self-hosting Inter under `static/` removes the dependency and the
`preconnect` pair with it.

### Where the front end is already in good shape

Stated so the list above is read in proportion. Contrast passes AA in both themes
on `/method` measured on a settled page. No horizontal overflow at 375 px on any
of the five pages. `:focus-visible` is styled everywhere and `outline:none`
appears nowhere in either stylesheet. Filter, URL round-trip, `aria-live` count,
panel focus trap, Escape-to-close and windowed paging all work as documented.
Stylesheets are content-hashed. `.well-known/security.txt` is present and
correct, and `CNAME` deploys. 797 offline tests pass in 13.7 s, ruff is clean, and
the nine skips are all deliberate live-network gates.

---

## Decisions for you, not defects

**D1. Which number is the headline?. ANSWERED, and stronger than either
option.** Jerry's call: the corroborated figure muddies the water, so drop the
calculation rather than repoint the meta tag. Done on 2026-08-27. `_indep`,
`_ORIGIN`, `indep_sources`, `single_origin` and `summary.corroborated` are all
gone; `schema_version` is 3; retired fields are stripped on read so every
pre-existing snapshot and dated archive is republished under the current
contract. `sources` and `refs` still ship in full, so independence stays
derivable by anyone who wants to compute it. What is gone is this site
publishing its own answer.

**D2. The first screen is one vendor.** Default sort is `days_public` descending,
and the top ten rows are all Android. `platform/packages/apps/Settings`,
`platform/frameworks/base`, all from OSV alone, all at 572 days. A site that
refuses to name a CNA opens on ten near-identical rows that name one vendor's
platform unmistakably. `/method` argues at length that visibility is not
behaviour; the default sort makes the opposite argument above the fold. Worth
considering a secondary sort key, or collapsing runs from one package.

**D3. 70% of the list is four days old.** `ghsa-repos` contributed 1,188 of 1,691
rows in my build, and the count moved 640 (08-24) to 1,608 (08-26) to 1,709
(today). Anyone who looked at the site last week and looks again after the
announcement sees a 2.7x jump. Better to say why in the announcement than to be
asked.

**D4. `/method` still carries a pre-launch checklist.** "What has to be true
before this is promoted", reading 8 of 8 met, on a site that is promoted. It is
good provenance and I would keep it, but in the past tense, and retitled, so it
reads as the record of a decision rather than a pending gate.

**D5. The epoch has probably expired as an option.** `epoch` is `None` and the
site has been live and indexable at ~1,700 rows since 08-26. Setting `RBP_EPOCH`
now would take a publicly indexed count to approximately zero and render the
launch-day zero state to readers who have already seen the real number. PLAN item
6 sequenced the epoch for launch day; launch day happened without it. My read is
that the epoch is now a worse option than carrying the backlog, and that the
zero-state work should stay in the tree as insurance rather than be triggered.
Your call, but it is a call now rather than a task.

**D6. `/status` is intermittently "incomplete", and the cause is upstream.** Four
of the six snapshots on `origin/data` are `degraded: true`; the live run right now
is clean. Every degradation traces to `ubuntu` truncating mid-pagination on a 503
(`error at offset 3000: HTTP Error 503`), which counts as `truncated` rather than
`capped` and therefore degrades the run. Roughly half of announcement-week runs
will render "This run is incomplete" as the first thing on `/status`. This is the
pipeline rather than the front end, and the honest options are to retry the failed
offset, or to classify a mid-pagination 503 on an otherwise-complete feed
distinctly from a feed that stopped early for an unknown reason. Not a launch
blocker; worth knowing before someone screenshots it.

**D7. Two smaller copy questions.** `templates/_about-copy.html:88` reads "If a
CVE ID this site *will* list should not be listed", holding-page tense, now
served at `/about-this-count.html` on a launched site. And the panel on `/`
reproduces most of `/about-this-count`, so the nav's "About" is largely a second
copy of what the front page already offers one click away. Both are fine to leave;
neither is fine to leave unnoticed.

---

## Also landed: less-than age filters

Not a review finding. Jerry asked for it alongside D1.

The `public` control only asked one direction: `90+`, `180+`, `365+`. It now asks
both, in one select with the direction in the option text rather than only in the
optgroup label, because a collapsed select shows the option alone and "90 days"
without a direction is ambiguous where "under 90 days" is not.

    at least   90+ days | 180+ days | 365+ days
    under      under 30 days | under 90 days | under 180 days

Three things worth recording about the choices:

**The thresholds are not invented.** 30 / 90 / 180 are the boundaries of
`summary.age_buckets`, which the site already publishes, so a reader who reads a
bucket count can now reproduce it as a filtered, linkable view instead of taking
it on trust. Verified against the live snapshot: `under 30 days` returns 347 and
the `7-30d` bucket is 347; `90+` returns 104 and `90-180d` + `180d+` is 34 + 70.

**The bounds partition.** Inclusive-min, exclusive-max, so `90+ days` and
`under 90 days` return 104 and 1,587 against a total of 1,691. No row satisfies
both and no row satisfies neither, which is a property a reader can check.

**Old links still resolve.** The control's URL parameter changed from `minage` to
`age` because the value now carries a direction (`?age=30-`), and a `?minage=90`
link shared before today would otherwise have silently lost its filter. `readUrl`
translates the old parameter, normalises `90` to `90+`, and the next write
migrates the URL. Verified: `?minage=180` lands on `180+ days`, 70 rows.

Two smaller things fixed in passing, both consequences of the rename: the
event listener bound the old element id, and "Clear filters" cleared a typed list
of three controls, so after the rename it would have left the age filter set and
the empty state on screen. It is derived from the control map now.

---

## Found while fixing, not in the original review

Three defects surfaced from guards written for other items. None was visible in
source, and two were invisible to a reader who only used a keyboard.

### F1. The open dialog was modal to Tab and not to the pointer

`.scrim` was `z-index: 30` and `.panel` `31`, against a `.header` at **1000**. So
the site header painted *over* the modal: never dimmed, and its nav links and
theme toggle still hittable through the scrim. The panel declares
`role="dialog" aria-modal="true"`, which tells assistive technology the rest of
the document is hidden; it was not, for anyone with a mouse. The keyboard focus
trap in `list.html` was added for exactly this concern and only ever covered Tab.

The modal layer is 1100/1101/1102 now, above the highest z-index in either
stylesheet rather than one greater than it.

### F2. The panel's Close button rode off the top on the first scroll

`.closebtn` was `position: absolute` inside a `position: fixed` panel that is its
own scroll container, so it was placed against the panel's padding box *including*
the scrolled-away part. The panel is ~3,500 px against a 900 px viewport, so past
the first screen the only **visible** way out of a modal dialog was gone. Escape
and the scrim still worked, which is exactly why nobody noticed: the keyboard
route was fine and the one a mouse user can see was not.

Found by a Playwright click on Close timing out and reporting that `#themeToggle`
was intercepting it, which is also how F1 surfaced.

### F3. A mobile touch-target rule was stretching a sentence

`style.css:819-827` gives every `button` `min-height: 44px` below 768 px. Correct
for everything it was written for; all of those are flex or block items. The
hedge's "Why" is the one button on the site that sits **inline** at the end of a
paragraph, and a 44 px inline-block inside a 19.7 px line box makes that line box
44 px. The hedge rendered with a visibly wider gap above its final line than
between any of the others, on the front page, at every width under 768 px.

Scoped override on `.listhedge .linkbtn`, with the target restored as a `::before`
overlay that grows outside the line box: 47×26, which clears WCAG 2.2 AA (2.5.8)
where the 44 px AAA target is what an inline context cannot have.

### And one fixture gap, which mattered more than the three

`tests/_sitefixture.py` gave every row an `advisory_url` but no `source_urls` and
only one per-feed date. `chips()` renders a source with no URL as a non-link
`<span>`, so **no row in any render test had ever produced a single `<a>` in the
list**: the front page's whole evidence layer, the feed chips and the per-feed
"open advisory" links, was unrendered in every browser test this project has. Any
assertion about those links would have passed vacuously rather than failed.

Caught because the M5 guard asserts it found links *before* it asserts anything
about them. That habit is worth keeping: it is the difference between a test that
works and a test that passes.

---

## After the review: a hard pivot, 2026-08-27

Not review findings. Jerry's calls, taken after Passes 1 and 2 shipped, and
recorded here because two of them weaken arguments this document makes elsewhere.

### The hedge above the rows is gone

"A floor, not a total. Only configured feeds are read, so rows exist that this
site cannot see. It does not say which CNA reserved any of these IDs."

It sat ahead of the first CVE deliberately: it had been a `<caption>` on the old
table, so the qualifier travelled with a copy, a print or a screen-reader pass of
the list.

**What this costs, and it touches D6's neighbour.** `NEXT.md` justified removing
the degraded banner partly on this hedge being a standing, unconditional
disclosure. That leg is gone. The floor claim survives in the panel (a hidden
dialog), on `/method`, and in `rbp.json`, and none of those travels with a
selection. So on a degraded run a reader who copies the rows carries neither the
floor caveat nor a note that the count is lower than usual. Three disclosures
remain where the argument assumed four. `tests/test_a11y.py` and
`tests/test_status.py` were inverted rather than deleted, and both now record the
gap in their docstrings.

### There is no removal channel and no email address

Retired from all five surfaces: the footer on every page, the panel, the About
copy, `/method`, and `.well-known/security.txt`.

Jerry's reasoning is the project's own, from when the automated channel went on
2026-08-26: a row is listed only after the CVE Services reservation endpoint
confirms the ID is reserved and unpublished, so there is nothing to correct, and
every row is an ID already referenced in a public advisory and held for the
reportable buffer, so there is nothing to withhold that is not already public.

**The cost, which accuracy does not reach.** The case the channel answered was the
**embargo**, not the error: a row that is entirely accurate and whose listing
still cuts across a live multi-party disclosure. Verification is that case's
premise rather than its fix. It now has no route on this site.

`security.txt` stays valid under RFC 9116 on the GitHub private-advisory URL
alone, and now states explicitly that its contact is for a vulnerability in this
site's own code and that the site operates no removal channel. **`RBP_WITHHOLD` is
untouched** and still tested: the capability is kept and not advertised.

`test_the_channel_that_does_exist_is_described_everywhere_it_is_offered` became
`test_no_surface_offers_a_removal_channel`, asserting the absence across every
template, because a promise that returns on one surface is worse than one that
never left. It would have been the fourth time a withhold ask went stale on a page
nobody re-read.

### UI chrome is title case

Control labels, options, optgroups, buttons, status chips and metric labels.
Prose is not: placeholders, empty-state sentences, card headings and body copy stay
sentence case, because title-casing a sentence reads as broken rather than tidy.

That sweep exposed one pre-existing bug. `chipLabel` built a screen-reader name as
`name + " advisory for " + cve`, and two feed names already end in "Advisory", so
CSAF rows announced "CSAF Advisory advisory for CVE-2026-1". Invisible while the
names were lower case. Zero doubled labels across 345 links now.

Three guards asserted lower-case string literals and are case-insensitive now:
what they are about is that a label exists, not how it is cased, and a guard that
fails on a styling change is one people learn to edit without reading.

---

## Proposed order of work

Three passes, each independently shippable, because `main` deploys to the live
site on push.

**Pass 1, the shared surface. DONE 2026-08-27.** B1, B2, B3, B4, B6, B7, H4.
Everything a reader encounters before they reach a page. What landed is recorded
under each item; three things are worth pulling out here.

*The card carries no count, and the review item asked for one.* Baking the number
into a committed image means it goes stale the moment the count moves and the card
contradicts `og:title` exactly the way `og:description` used to; generating it
per-run means Pillow on a publish path that runs four times a day on pandas,
pyarrow and Jinja2, against PLAN 8e. So `tools/make_brand_assets.py` is an
authoring tool, run by hand, output committed, and the live count travels in
`og:title` and `og:description` as it already did. The upgrade path if you ever
want the number in the image is pre-rendered digit sprites composited with a
stdlib PNG writer; it is about 150 lines and I would not add it for this.

*B2 came forward.* The 404 page has to use root-absolute links, because GitHub
Pages serves it for an unmatched path at any depth and relative URLs would resolve
against a directory that does not exist, including both stylesheets, so the page
would arrive unstyled as well as unnavigable. Teaching the link checkers about
root-absolute hrefs meant widening them off the `.html`-only pattern, which
immediately failed on `data/schema.json`. Fixing the checker without fixing what
it found would have been knowingly shipping a dead link, so B2 landed here.

*Two guards caught real gaps while being written.* The icon sweep found that the
pre-launch holding page, which is standalone by design, inherited none of
`base.html`'s head and so had no favicon at all, and that is the page the
coverage gate demotes `/` to without a commit. The copy sweeps correctly caught
`404.html` as a new page: its meta description now leads with the legitimacy
claim, and its exemption from the delegation caveat is argued in
`_NO_ROW_LEVEL_CLAIM` rather than just added.

**Pass 2, the front page. DONE 2026-08-27.** B5, H1, H2, H3, M1, M5.

Each fix carries a guard that fails without it, mutation-tested by reintroducing
the defect: seven new tests, one offline (structure) and six in the browser suite.
That the whole suite was green before any of them is the point, none of these six
had anything watching them.

The offline structural check covers H1 and H2 together and runs over every built
page in both postures: exactly one `<main>`, no duplicate `id`, and balanced open
and close tags for six elements. Both defects fail it independently.

**Pass 3, the rest.** M2, M3, M4, M6, M7, M8, and whichever of D2/D4/D7 you
want changed.

Each pass gets the project's own standard applied to it: mutation-test every fix
by reintroducing the defect and confirming a test fails. Three of the findings
above (B2, B5, H1) sit in exactly the gap `NEXT.md` names, a green suite reading
a file, a breakpoint or a pattern that no longer describes what ships, so a fix
that does not come with a guard that fails without it has not been finished.

### What I would want to add to the suite alongside the fixes

- The `.html`-only link pattern widened to every internal `href`, in both copies.
- An assertion that the unfurl count and the rendered `<h1>` count are the same
  string, in both postures. That is the invariant B1 broke.
- One built-page structural check: exactly one `<main>`, no duplicate `id`,
  balanced `div` open and close. All three of H1 and H2 fall out of it.
- A mobile-viewport render test asserting the `<h1>`'s accessible name still
  contains its unit below 640 px.

---

## Reproducing this

The local build used the 2026-08-27 snapshot from `origin/data`, which is now in
`snapshots/2026-08-27/` (gitignored), with `runs.jsonl` copied to `data/`:

```bash
RBP_LAUNCHED=1 python -m rbp.cli build --out /tmp/rbp-site
```

Live checks were plain `curl` against `https://rbptracker.org/` and a headless
browser at 1440x900 and 375x812.
