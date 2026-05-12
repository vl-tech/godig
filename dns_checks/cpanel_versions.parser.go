package dns_checks

import (
	_ "embed"
	"encoding/csv"
	"fmt"
	"strings"
	"time"
)

//go:embed cpanel_versions.csv
var cpanelVersionsCSV []byte

type cpanelOSRecord struct {
	OSFamily         string
	OSName           string
	OSVersion        string
	EOLDate          string
	SupportedVersion string
}

func (v cpanelOSRecord) isEOL() bool {
	if v.EOLDate == "" {
		return false
	}
	parsed, err := time.Parse("2006-01-02", v.EOLDate)
	if err != nil {
		return false
	}
	return parsed.Before(time.Now())
}

func loadCpanelVersions() ([]cpanelOSRecord, error) {
	reader := csv.NewReader(strings.NewReader(string(cpanelVersionsCSV)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	var versions []cpanelOSRecord
	for _, row := range records[1:] {
		versions = append(versions, cpanelOSRecord{
			OSFamily:         row[0],
			OSName:           row[1],
			OSVersion:        row[2],
			EOLDate:          row[3],
			SupportedVersion: row[4],
		})
	}
	return versions, nil
}

func CpanelEolCsvData(filterFamily string, eolOnly bool) {
	versions, err := loadCpanelVersions()
	if err != nil {
		fmt.Println("Error loading cPanel OS data:", err)
		return
	}

	t.Println("cPanel Supported OS Versions")
	y.Println(strings.Repeat("-", 55))

	for _, v := range versions {
		if filterFamily != "" && !strings.EqualFold(v.OSFamily, filterFamily) {
			continue
		}
		if eolOnly && !v.isEOL() {
			continue
		}

		cpanelVer := v.SupportedVersion
		if cpanelVer == "" {
			cpanelVer = "N/A"
		}
		eolDate := v.EOLDate
		if eolDate == "" {
			eolDate = "N/A"
		}

		if v.isEOL() {
			r.Printf("  %-28s %-18s EOL: %-12s  cPanel: %s\n", v.OSName, v.OSVersion, eolDate, cpanelVer)
		} else {
			g.Printf("  %-28s %-18s EOL: %-12s  cPanel: %s\n", v.OSName, v.OSVersion, eolDate, cpanelVer)
		}
	}
	fmt.Println()
}
