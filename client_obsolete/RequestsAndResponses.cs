using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace VsSessionServer;

public enum NotificationType
{
    ProcessRestarted = 1,
    SessionTerminated = 2
}

public class VsSessionChangeNotification
{
    [Required]
    [JsonPropertyName("notification_type")]
    public NotificationType NotificationType { get; set; }

    [JsonPropertyName("pid")]
    public ushort PID { get; set; }

    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = string.Empty;

    public override string ToString()
    {
        var maybePID = this.PID != 0 ? $" (PID: {this.PID})" : string.Empty;
        return $"Session {this.SessionId}: {Enum.GetName(typeof(NotificationType), this.NotificationType)}{maybePID}";
    }
}

public class EnvVar
{
    [Required]
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public string? Value { get; set; }
}

public class VsSessionRequest
{
    [Required]
    [JsonPropertyName("project_path")]
    public string ProjectPath { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("debug")]
    public bool Debug { get; set; }

    [JsonPropertyName("env")]
    public List<EnvVar> Environment { get; set; } = new List<EnvVar>();

    [JsonPropertyName("args")]
    public List<string> Arguments { get; set; } = new List<string>();
}
