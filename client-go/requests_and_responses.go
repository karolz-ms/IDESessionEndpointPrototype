package main

import (
	"fmt"
)

type notificationType string

const (
	notificationTypeProcessRestarted  notificationType = "processRestarted"
	notificationTypeSessionTerminated notificationType = "sessionTerminated"
	notificationTypeServiceLogs       notificationType = "serviceLogs"
	notificationTypeProtected         notificationType = "protected"
)

type ideSessionNotificationBase struct {
	NotificationType notificationType `json:"notification_type"`
	SessionID        string           `json:"session_id,omitempty"`
}

func (snb *ideSessionNotificationBase) String() string {
	retval := fmt.Sprintf("Session %s: %s", snb.SessionID, snb.NotificationType)
	return retval
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
	IsStdErr   bool   `json:"is_std_err,omitempty"`
	LogMessage string `json:"log_message"`
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
