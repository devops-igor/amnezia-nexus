// Command ru-inventory regenerates the committed Russian IPv4 allocation
// inventory (issue #919) from a zone file that was downloaded separately.
//
// It is the only supported way to update the artifact, and it never fetches:
// the operator downloads the zone, this command validates it, and only then
// replaces the committed files. That keeps the build offline, keeps two builds
// of the same revision routing identically, and puts the validation in front of
// the commit instead of in front of an operator's eyes.
//
// Usage, from the repository root:
//
//	curl -fsSL https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone \
//	  | go run ./cmd/ru-inventory -url https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone -retrieved 2026-11-19
//
// A rejected body leaves the committed artifact untouched and exits non-zero.
// The two committed files are then replaced by separate renames, so a run that
// fails between them leaves a mixed pair that the loader refuses; re-running the
// command rewrites both from one matching zone. Use -dry-run to validate and
// report without writing.
//
// A body that keeps fewer than policy.MaxInventoryReductionPercent of the
// committed prefixes is refused as a truncated feed; pass
// -allow-large-reduction for a deliberate large change. The comparison needs a
// count of the committed artifact; when that count cannot be established the run
// is refused rather than applied without a guard.
//
// The upstream copyright notice (Copyrights.txt) ships with the artifact and is
// embedded in the binary; this command never writes or replaces it, because the
// redistribution terms require it to stay intact.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// maxZoneBytes bounds the body read from stdin. The published zone is about
// 135 KB; the bound exists so a mistaken input (a video, a database dump) fails
// as a size error rather than being parsed for minutes.
const maxZoneBytes = 8 << 20

func main() {
	if err := run(os.Stdin, os.Stdout, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ru-inventory: %v\n", err)
		os.Exit(1)
	}
}

// options holds the invocation's flags.
type options struct {
	dir                 string
	source              string
	sourceURL           string
	retrieved           string
	dryRun              bool
	allowLargeReduction bool
}

// provenance returns the descriptive provenance fields for this invocation.
// The prefix count, data digest and notice digest are not taken from the
// operator: they are derived from what ships by the validator.
func (o options) provenance() policy.InventoryProvenance {
	return policy.InventoryProvenance{
		Source:      o.source,
		SourceURL:   o.sourceURL,
		RetrievedAt: o.retrieved,
	}
}

// updateOptions returns the maintenance decisions for this invocation, including
// the count the body is compared against. A baseline that cannot be established
// is an error: the caller must refuse the update rather than compare against
// nothing.
func (o options) updateOptions() (policy.InventoryUpdateOptions, error) {
	previous, err := policy.PreviousInventoryCount(o.dir)
	if err != nil {
		return policy.InventoryUpdateOptions{}, err
	}
	return policy.InventoryUpdateOptions{
		PreviousPrefixCount: previous,
		AllowLargeReduction: o.allowLargeReduction,
	}, nil
}

func run(stdin io.Reader, stdout io.Writer, args []string) error {
	opts, err := parseOptions(stdout, args)
	if err != nil {
		return err
	}
	update, err := opts.updateOptions()
	if err != nil {
		return describeRejection(err)
	}
	body, err := readZone(stdin)
	if err != nil {
		return err
	}
	record, meta, err := policy.ValidateInventoryUpdate(body, opts.provenance(), update)
	if err != nil {
		return describeRejection(err)
	}
	if !opts.dryRun {
		if err := policy.WriteInventoryArtifact(opts.dir, body, meta); err != nil {
			return err
		}
	}
	return report(stdout, opts, update.PreviousPrefixCount, record)
}

func parseOptions(stdout io.Writer, args []string) (options, error) {
	fs := flag.NewFlagSet("ru-inventory", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var opts options
	fs.StringVar(&opts.dir, "dir", policy.InventoryArtifactDir, "directory holding the committed inventory artifact")
	fs.StringVar(&opts.source, "source", "ipdeny", "feed that published the zone")
	fs.StringVar(&opts.sourceURL, "url", "", "exact URL the zone was downloaded from (required)")
	fs.StringVar(&opts.retrieved, "retrieved", "", "retrieval date in UTC, YYYY-MM-DD (required)")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "validate and report without writing the artifact")
	fs.BoolVar(&opts.allowLargeReduction, policy.InventoryLargeReductionFlag, false,
		fmt.Sprintf("accept a body that keeps fewer than %d%% of the committed prefixes", policy.MaxInventoryReductionPercent))
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q: the zone is read from stdin", fs.Arg(0))
	}
	return opts, nil
}

// readZone reads the downloaded zone body, refusing an input larger than any
// plausible zone.
func readZone(stdin io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(stdin, maxZoneBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read zone from stdin: %w", err)
	}
	if len(body) > maxZoneBytes {
		return nil, fmt.Errorf("zone exceeds the %d byte input bound", maxZoneBytes)
	}
	return body, nil
}

// describeRejection keeps the wrapped validation error, adding what the operator
// most needs to know: the committed artifact was not touched.
func describeRejection(err error) error {
	switch {
	case errors.Is(err, policy.ErrInventoryNotPrefixList):
		return fmt.Errorf("zone rejected, committed inventory left unchanged: %w", err)
	case errors.Is(err, policy.ErrInventoryLargeReduction):
		return fmt.Errorf("zone rejected, committed inventory left unchanged: %w", err)
	case errors.Is(err, policy.ErrInventoryBaselineUnavailable):
		return fmt.Errorf("zone not applied, committed inventory left unchanged: %w", err)
	default:
		return err
	}
}

func report(stdout io.Writer, opts options, previous int, record policy.InventoryProvenance) error {
	fmt.Fprintf(stdout, "source: %s\n", record.Source)
	fmt.Fprintf(stdout, "source_url: %s\n", record.SourceURL)
	fmt.Fprintf(stdout, "retrieved_at: %s\n", record.RetrievedAt)
	fmt.Fprintf(stdout, "prefix_count: %d\n", record.PrefixCount)
	if previous > 0 {
		fmt.Fprintf(stdout, "previous_prefix_count: %d\n", previous)
	}
	fmt.Fprintf(stdout, "sha256: %s\n", record.SHA256)
	fmt.Fprintf(stdout, "notice: %s %s\n", record.NoticeFile, record.NoticeSHA256)
	if opts.dryRun {
		fmt.Fprintln(stdout, "dry_run: true (nothing written)")
		return nil
	}
	fmt.Fprintf(stdout, "data: %s\n", policy.InventoryDataPath(opts.dir))
	fmt.Fprintf(stdout, "provenance: %s\n", policy.InventoryMetaPath(opts.dir))
	return nil
}
