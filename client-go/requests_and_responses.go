package main

import (
	"fmt"
)

type notificationType string

const (
	notificationTypeProcessRestarted  notificationType = "processRestarted"
	notificationTypeSessionTerminated notificationType = "sessionTerminated"
	notificationTypeServiceLogs       notificationType = "serviceLogs"
)

type ideSessionNotificationBase struct {
	NotificationType notificationType `json:"notification_type"`
	SessionID        string           `json:"session_id,omitempty"`
}

type ideRunSessionProcessChangedNotification struct {
	ideSessionNotificationBase
	PID int64 `json:"pid,omitempty"`
}

type ideRunSessionTerminatedNotification struct {
	ideRunSessionProcessChangedNotification
	ExitCode *int32 `json:"exit_code,omitempty"`
}

type ideSessionLogNotification struct {
	ideSessionNotificationBase
	IsStdErr   bool   `json:"is_std_err"`
	LogMessage string `json:"log_message"`
}

func (pcn *ideRunSessionProcessChangedNotification) ToString() string {
	maybePID := ""
	if pcn.PID != 0 {
		maybePID = fmt.Sprintf(" (PID: %d)", pcn.PID)
	}
	retval := fmt.Sprintf("Session %s: %s%s", pcn.SessionID, pcn.NotificationType, maybePID)
	return retval
}

type EnvVar struct {
	// Name of the environment variable
	Name string `json:"name"`

	// Value of the environment variable. Defaults to "" (empty string).
	// +optional
	Value string `json:"value,omitempty"`
	// CONSIDER allowing expansion of existing variable references e.g. using ${VAR_NAME} syntax and $$ to escape the $ sign
}

type VsSessionRequest struct {
	ProjectPath string   `json:"project_path"`
	Debug       bool     `json:"debug"`
	Env         []EnvVar `json:"env,omitempty"`
	Arguments   []string `json:"args,omitempty"`
}

type VsServerInfo struct {
	IdentityToken string `json:"identity_token"`
}
