package models

import (
	"time"
)

// ServerItemResponse represents server data in responses.
type ServerItemResponse struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	Host        string         `json:"host"`
	SSHPort     int            `json:"ssh_port"`
	Username    string         `json:"username"`
	ServerInfo  string         `json:"server_info,omitempty"`
	Protocols   map[string]any `json:"protocols"`
	CreatedAt   *time.Time     `json:"created_at,omitempty"`
	Status      string         `json:"status,omitempty"`
	LatencyMS   *int           `json:"latency_ms,omitempty"`
	LastChecked *string        `json:"last_checked,omitempty"`
	Reachable   *bool          `json:"reachable,omitempty"`
}

// ServerStatsResponse represents server resource telemetry.
type ServerStatsResponse struct {
	CPU         float64 `json:"cpu"`
	RAMUsed     int64   `json:"ram_used"`
	RAMTotal    int64   `json:"ram_total"`
	RAMPercent  float64 `json:"ram_percent"`
	DiskUsed    int64   `json:"disk_used"`
	DiskTotal   int64   `json:"disk_total"`
	DiskPercent float64 `json:"disk_percent"`
	NetRx       int64   `json:"net_rx"`
	NetTx       int64   `json:"net_tx"`
	Uptime      string  `json:"uptime"`
}

// ServerCheckResponse represents server connectivity check result.
type ServerCheckResponse struct {
	Connection      string         `json:"connection"`
	DockerInstalled bool           `json:"docker_installed"`
	Protocols       map[string]any `json:"protocols"`
}

// UserItemResponse represents user data in responses.
type UserItemResponse struct {
	ID                   string  `json:"id"`
	Username             string  `json:"username"`
	Role                 string  `json:"role"`
	Enabled              bool    `json:"enabled"`
	CreatedAt            string  `json:"created_at"`
	TelegramID           *string `json:"telegramId,omitempty"`
	Email                *string `json:"email,omitempty"`
	Description          *string `json:"description,omitempty"`
	ConnectionsCount     int     `json:"connections_count"`
	TrafficUsed          int64   `json:"traffic_used"`
	TrafficTotal         int64   `json:"traffic_total"`
	TrafficLimit         int64   `json:"traffic_limit"`
	TrafficResetStrategy string  `json:"traffic_reset_strategy"`
	LastResetAt          *string `json:"last_reset_at,omitempty"`
	ExpirationDate       *string `json:"expiration_date,omitempty"`
	ExpiresAt            *string `json:"expires_at,omitempty"`
	AWGMimicry           *string `json:"awg_mimicry,omitempty"`
	ShareEnabled         bool    `json:"share_enabled"`
	ShareToken           *string `json:"share_token,omitempty"`
	HasSharePassword     bool    `json:"has_share_password"`
	Source               string  `json:"source"`
}

// PaginatedUsersResponse represents paginated user list response.
type PaginatedUsersResponse struct {
	Users []UserItemResponse `json:"users"`
	Total int                `json:"total"`
	Page  int                `json:"page"`
	Size  int                `json:"size"`
	Pages int                `json:"pages"`
}

// LeaderboardEntryResponse represents ranked user in leaderboard response.
type LeaderboardEntryResponse struct {
	Rank     int    `json:"rank"`
	Username string `json:"username"`
	Download int64  `json:"download"`
	Upload   int64  `json:"upload"`
	Total    int64  `json:"total"`
}

// LeaderboardResponse represents leaderboard response.
type LeaderboardResponse struct {
	Period          string                     `json:"period"`
	Entries         []LeaderboardEntryResponse `json:"entries"`
	CurrentUserRank *int                       `json:"current_user_rank,omitempty"`
	MonthlyLabel    *string                    `json:"monthly_label,omitempty"`
}
