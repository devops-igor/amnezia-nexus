package handlers

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

var statsSectionPattern = regexp.MustCompile(`===(CPU|RAM|DISK|NET|UPTIME)===`)

func parseCPU(cpuStr string) (float64, error) {
	str := strings.TrimSpace(cpuStr)
	if str == "" {
		return 0, errors.New("empty cpu section")
	}
	val, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid cpu metric %q: %w", str, err)
	}
	if val < 0 {
		return 0, fmt.Errorf("negative cpu metric: %f", val)
	}
	return val, nil
}

func parseUsagePair(sectionName, content string) (int64, int64, float64, error) {
	parts := strings.Fields(content)
	if len(parts) < 2 {
		return 0, 0, 0, fmt.Errorf("malformed %s section: expected at least 2 fields, got %d", sectionName, len(parts))
	}
	used, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid %s used metric %q: %w", sectionName, parts[0], err)
	}
	if used < 0 {
		return 0, 0, 0, fmt.Errorf("negative %s used metric: %d", sectionName, used)
	}
	total, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid %s total metric %q: %w", sectionName, parts[1], err)
	}
	if total <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid non-positive %s total metric: %d", sectionName, total)
	}
	percent := float64(used) / float64(total) * 100.0
	return used, total, percent, nil
}

func parseNetPair(content string) (int64, int64, error) {
	parts := strings.Fields(content)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("malformed net section: expected at least 2 fields, got %d", len(parts))
	}
	rx, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid net rx metric %q: %w", parts[0], err)
	}
	if rx < 0 {
		return 0, 0, fmt.Errorf("negative net rx metric: %d", rx)
	}
	tx, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid net tx metric %q: %w", parts[1], err)
	}
	if tx < 0 {
		return 0, 0, fmt.Errorf("negative net tx metric: %d", tx)
	}
	return rx, tx, nil
}

func parseCombinedStats(raw string) (models.ServerStatsResponse, error) {
	if strings.TrimSpace(raw) == "" {
		return models.ServerStatsResponse{}, errors.New("empty stats output")
	}

	var resp models.ServerStatsResponse
	sections := make(map[string]string)

	matches := statsSectionPattern.FindAllStringIndex(raw, -1)
	for i, m := range matches {
		name := raw[m[0]+3 : m[1]-3]
		start := m[1]
		end := len(raw)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		sections[name] = strings.TrimSpace(raw[start:end])
	}

	cpuStr, ok := sections["CPU"]
	if !ok {
		return models.ServerStatsResponse{}, errors.New("missing cpu section")
	}
	cpuVal, err := parseCPU(cpuStr)
	if err != nil {
		return models.ServerStatsResponse{}, err
	}
	resp.CPU = cpuVal

	ramStr, ok := sections["RAM"]
	if !ok {
		return models.ServerStatsResponse{}, errors.New("missing ram section")
	}
	usedRAM, totalRAM, ramPct, err := parseUsagePair("ram", ramStr)
	if err != nil {
		return models.ServerStatsResponse{}, err
	}
	resp.RAMUsed = usedRAM
	resp.RAMTotal = totalRAM
	resp.RAMPercent = ramPct

	diskStr, ok := sections["DISK"]
	if !ok {
		return models.ServerStatsResponse{}, errors.New("missing disk section")
	}
	usedDisk, totalDisk, diskPct, err := parseUsagePair("disk", diskStr)
	if err != nil {
		return models.ServerStatsResponse{}, err
	}
	resp.DiskUsed = usedDisk
	resp.DiskTotal = totalDisk
	resp.DiskPercent = diskPct

	netStr, ok := sections["NET"]
	if !ok {
		return models.ServerStatsResponse{}, errors.New("missing net section")
	}
	rx, tx, err := parseNetPair(netStr)
	if err != nil {
		return models.ServerStatsResponse{}, err
	}
	resp.NetRx = rx
	resp.NetTx = tx

	if uptimeStr, ok := sections["UPTIME"]; ok {
		resp.Uptime = uptimeStr
	}

	return resp, nil
}
