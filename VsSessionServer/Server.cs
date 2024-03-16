using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Linq;
using System.Net.WebSockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.IO;
using Microsoft.AspNetCore.Http.HttpResults;

namespace VsSessionServer;

internal record RunSessionSubscription(WebSocket Socket, TaskCompletionSource Tcs);

internal class RunSessionState
{
    public string SessionId { get; set; } = string.Empty;
    public ushort PID { get; set; }
    public bool Done { get; set; }
    public VsSessionRequest? Request { get; set; }
}

public class Server
{
    private ConcurrentDictionary<string, RunSessionState> sessions = new ConcurrentDictionary<string, RunSessionState>();
    private Random random = new Random();
    private List<RunSessionSubscription> subscriptions = new List<RunSessionSubscription>();
    private readonly bool encryptSensitivePayloads;
    private readonly Aes? aes;

    public Server(bool encryptSensitivePayloads = false)
    {
        this.encryptSensitivePayloads = encryptSensitivePayloads;
        if (this.encryptSensitivePayloads)
        {
            this.aes = Aes.Create();
            Console.WriteLine($"Using AES encryption with key {Convert.ToBase64String(this.aes.Key)}");
        }
    }

    private static JsonSerializerOptions jsonSerializerOpts = new JsonSerializerOptions {
        Converters =
        {
            new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false)
        }
    };

    public async Task<Results<Created<string>, ProblemHttpResult>> SessionPut(HttpContext context)
    {
        if (!context.Request.HasJsonContentType())
        {
            return TypedResults.Problem("Request must have application/json content type", null, StatusCodes.Status415UnsupportedMediaType);
        }

        byte[] payload;
        if (this.encryptSensitivePayloads)
        {
            var encryptedPayload = JsonSerializer.Deserialize<EncryptedPayload>(context.Request.BodyReader.AsStream(), jsonSerializerOpts);
            if (encryptedPayload is null)
            {
                return TypedResults.Problem("Request body could not be deserialized", null, StatusCodes.Status400BadRequest);
            }
            
            var ciphertext = Convert.FromBase64String(encryptedPayload.Ciphertext);
            var iv = Convert.FromBase64String(encryptedPayload.InitializationVector);
            payload = this.aes!.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        } else
        {
            var ms = new MemoryStream();
            await context.Request.BodyReader.CopyToAsync(ms);
            payload = ms.ToArray();
        }

        var sr = JsonSerializer.Deserialize<VsSessionRequest>(payload, jsonSerializerOpts);
        if (sr is null)
        {
            return TypedResults.Problem("Request body could not be deserialized", null, StatusCodes.Status400BadRequest);
        }

        string sessionId = NewSessionId();
        var rss = new RunSessionState { 
            SessionId = sessionId,
            PID = NewProcessId(),
            Done = false,
            Request = sr
        };
        if (!this.sessions.TryAdd(sessionId, rss))
        {
            return TypedResults.Problem("Session could not be created", null, StatusCodes.Status500InternalServerError);
        }

        Console.WriteLine($"Started session {sessionId} from request {sr.ToString()}");
        Console.WriteLine($"Started process {rss.PID} for session {sessionId}");

        // Simulate some session events and session termination.
        _ = Task.Run(async() => {
            await Task.Delay(TimeSpan.FromSeconds(1));
            await SimulateProcessRestartAsync(sessionId);
        });
        _ = Task.Run(async () => {
            await Task.Delay(TimeSpan.FromSeconds(3));
            await SimulateLogsAsync(sessionId, "Making some progress...");
        });
        _ = Task.Run(async () => {
            await Task.Delay(TimeSpan.FromSeconds(5));
            await SimulateLogsAsync(sessionId, "Almost there...");
        });
        _ = Task.Run(async () => {
            await Task.Delay(TimeSpan.FromSeconds(7));
            await SimulateSessionEndAsync(sessionId);
        });


        return TypedResults.Created((context.Request.Path + $"/{sessionId}").ToString(), "Session created");
    }

    public async Task SessionNotify(HttpContext context)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        using var webSocket = await context.WebSockets.AcceptWebSocketAsync();
        var socketTcs = new TaskCompletionSource();
        lock(this.subscriptions)
        {
            this.subscriptions.Add(new RunSessionSubscription(webSocket, socketTcs));
        }
        await socketTcs.Task;
    }

    private string NewSessionId()
    {
        const int sessionIdLength = 6;
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var id = string.Concat(Enumerable.Repeat(false, sessionIdLength).Select(_ => chars[this.random.Next(chars.Length)]));
        return id;
    }

    private ushort NewProcessId()
    {
        // For te sake of this sample, let's assume the process IDs range from 1000 to 60000.
        return (ushort) (this.random.Next(60000 - 1000) + 1000);
    }

    private Task SimulateProcessRestartAsync(string sessionId)
    {
        if (this.sessions.TryGetValue(sessionId, out var rss))
        {
            rss.PID = NewProcessId();
            this.sessions[sessionId] = rss;
            var prn = new ProcessRestartedNotification {
                PID = rss.PID,
                SessionId = sessionId
            };

            Console.WriteLine($"Process restarted for session {sessionId}, new PID is {rss.PID}");

            return UpdateSubscribersAsync(prn);
        } else
        {
            return Task.CompletedTask;
        }
    }

    private Task SimulateSessionEndAsync(string sessionId)
    {
        if (this.sessions.TryRemove(sessionId, out var _))
        {
            var stn = new SessionTerminatedNotification
            {
                SessionId = sessionId,
                ExitCode = 0 // We are all about success
            };

            Console.WriteLine($"Session {sessionId} ended");

            return UpdateSubscribersAsync(stn);
        } else
        {
            return Task.CompletedTask;
        }
    }

    private Task SimulateLogsAsync(string sessionId, string message)
    {
        // TODO: encrypt the payload if encryptSensitivePayloads is true

        var sln = new ServiceLogsNotification
        {
            SessionId = sessionId,
            IsStdErr = false,
            LogMessage = message
        };

        Console.WriteLine($"Session {sessionId} logs: {message}");

        return UpdateSubscribersAsync(sln);
    }

    private async Task UpdateSubscribersAsync<CT>(CT change) where CT : VsSessionNotification
    {
        // Iterating backwards to allow removing subscriptions for clients that are no longer listening.
        // The other code in the Server only adds subscriptions, so once we get the Count here,
        // we can assume nothing will change the slice of the subscription list [0, Count].
        int sCount = 0;
        lock(this.subscriptions)
        {
            sCount = this.subscriptions.Count;
        }

        for(int i = sCount -1; i >=0; i--)
        {
            RunSessionSubscription s = this.subscriptions[i];
            try
            {
                var payload = JsonSerializer.SerializeToUtf8Bytes<CT>(change, jsonSerializerOpts);
                await s.Socket.SendAsync(payload, WebSocketMessageType.Text, WebSocketMessageFlags.EndOfMessage, CancellationToken.None);
            } 
            catch
            {
                // Most likely the client just disconnected
                lock(this.subscriptions)
                {
                    this.subscriptions.RemoveAt(i);
                    s.Tcs.SetResult();
                }
            }
            
        }
    }
}
