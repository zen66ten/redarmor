package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"
)

// WriteTable renders results as a stdout-style table. Healthy/expired
// results are sorted by days remaining ascending, so the most urgent
// row is on top. Results with Err set are reported separately at the
// bottom, so a handful of unreachable hosts doesn't push real cert data
// out of view.
func WriteTable(w io.Writer, results []Result) error {
	var ok, failed []Result
	for _, r := range results {
		if r.Err != nil {
			failed = append(failed, r)
			continue
		}
		ok = append(ok, r)
	}

	sort.Slice(ok, func(i, j int) bool { return ok[i].DaysLeft < ok[j].DaysLeft })
	sort.Slice(failed, func(i, j int) bool { return failed[i].Host < failed[j].Host })

	if len(failed) > 0 {
		if _, err := fmt.Fprintf(w, "WARNING: %d host(s) failed to check, see bottom of report\n\n", len(failed)); err != nil {
			return err
		}
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tPORT\tSTATUS\tDAYS LEFT\tNOT AFTER\tISSUER")
	for _, r := range ok {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			r.Host, r.Port, r.Status, r.DaysLeft, r.NotAfter.Format(time.RFC3339), r.Issuer)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(failed) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Erroneous hosts:")
		ftw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(ftw, "HOST\tPORT\tERROR")
		for _, r := range failed {
			fmt.Fprintf(ftw, "%s\t%s\t%s\n", r.Host, r.Port, r.Err)
		}
		if err := ftw.Flush(); err != nil {
			return err
		}
	}

	return nil
}

// resultJSON mirrors Result for JSON output. It exists because Result.Err
// is an error interface, which encoding/json cannot serialize meaningfully
// on its own (most concrete error types have unexported fields and would
// marshal to "{}", silently losing the failure message).
type resultJSON struct {
	Host     string    `json:"host"`
	Port     string    `json:"port"`
	NotAfter time.Time `json:"notAfter"`
	DaysLeft int       `json:"daysLeft"`
	Issuer   string    `json:"issuer"`
	Serial   string    `json:"serial"`
	Status   Status    `json:"status"`
	Err      string    `json:"error,omitempty"`
}

// WriteJSON renders results as an indented JSON array.
func WriteJSON(w io.Writer, results []Result) error {
	out := make([]resultJSON, len(results))
	for i, r := range results {
		out[i] = resultJSON{
			Host:     r.Host,
			Port:     r.Port,
			NotAfter: r.NotAfter,
			DaysLeft: r.DaysLeft,
			Issuer:   r.Issuer,
			Serial:   r.Serial,
			Status:   r.Status,
		}
		if r.Err != nil {
			out[i].Err = r.Err.Error()
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}