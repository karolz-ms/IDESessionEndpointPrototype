using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Json.Serialization;

namespace VsSessionServer;

public static class NotificationTypes
{
    public static readonly string ProcessRestarted = "processRestarted";
    public static readonly string SessionTerminated = "sessionTerminated";
    public static readonly string ServiceLogs = "serviceLogs";
    public static readonly string ProtectedNotification = "protected";
}

public class VsSessionNotification
{
    [Required]
    [JsonPropertyName("notification_type")]
    public virtual string? NotificationType { get; set; }

    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = string.Empty;
}

public class ProcessRestartedNotification : VsSessionNotification
{
    [JsonPropertyName("notification_type")]
    public override string NotificationType => NotificationTypes.ProcessRestarted;

    [JsonPropertyName("pid")]
    public ulong PID { get; set; }
}

public class SessionTerminatedNotification : VsSessionNotification
{
    [JsonPropertyName("notification_type")]
    public override string NotificationType => NotificationTypes.SessionTerminated;

    [JsonPropertyName("exit_code")]
    public uint ExitCode { get; set; }
}

public class  ServiceLogsNotification : VsSessionNotification
{
    [JsonPropertyName("notification_type")]
    public override string NotificationType => NotificationTypes.ServiceLogs;

    [Required]
    [JsonPropertyName("is_std_err")]
    public bool IsStdErr { get; set; }

    [JsonPropertyName("log_message")]
    public string LogMessage { get; set; } = string.Empty;
}

public class ProtectedNotification : VsSessionNotification
{
    [JsonPropertyName("notification_type")]
    public override string NotificationType => NotificationTypes.ProtectedNotification;

    [Required]
    [JsonPropertyName("data")]
    public EncryptedPayload Data { get; set; }
}

public class EnvVar
{
    [Required]
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public string? Value { get; set; }

    public override string ToString()
    {
        return $"[{this.Name}: '{this.Value ?? ""}']";
    }
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

    public override string ToString()
    {
        string debugInfo = this.Debug ? "with debugger" : "without debugger";
        var sb = new StringBuilder();
        
        sb.AppendLine($"Request to run project {this.ProjectPath} {debugInfo}");
        
        if (this.Environment.Count > 0)
        {
            sb.AppendLine("Environment:");
            foreach (var env in this.Environment)
            {
                sb.AppendLine("    " + env.ToString());
            }
        } 
        else
        {
            sb.AppendLine("Environment: (empty)");
        }

        if (this.Arguments.Count > 0)
        {
            sb.AppendLine("Arguments:");
            foreach (var arg in this.Arguments)
            {
                sb.AppendLine("    " + arg);
            }
        }

        return sb.ToString();
    }
}

public class EncryptedPayload
{
    /// <summary>
    /// The AES-encrypted, base64-encoded payload.
    /// </summary>
    [Required]
    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty;

    /// <summary>
    /// The base64-encoded initialization vector for the encryption algorithm.
    /// </summary>
    [Required]
    [JsonPropertyName("iv")]
    public string InitializationVector { get; set; } = string.Empty;

    /// <summary>
    /// The base64-encoded authentication tag (signature) of the payload.
    /// To compute the signature, (un-encoded) initialization vector and ciphertext
    /// are concatenated, then the signature is computed over the result using HMACSHA256 algorithm..
    [Required]
    [JsonPropertyName("authentication_tag")]
    public string AuthenticationTag { get; set; } = string.Empty;
}



