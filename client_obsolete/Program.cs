using System;
using System.CommandLine;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using VsSessionClient;
using VsSessionServer;

var jsonSerializerOpts = new JsonSerializerOptions
{
    Converters =
    {
        new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false)
    }
};

var serverAddressOption = new Option<string>(
    name: "--server",
    description: "The address of the session server (host & port, e.g. localhost:5566"
);
serverAddressOption.IsRequired = true;

var rootCommand = new RootCommand("A VS session server demo client");
rootCommand.AddOption(serverAddressOption);

var listenForSessionUpdates = async (string serverAddress, CancellationToken ct) => {
    using var ws = new ClientWebSocket();
    try
    {
        await ws.ConnectAsync(new Uri($"ws://{serverAddress}/run_session/notify"), ct);
    }
    catch (Exception ex)
    {
        Console.WriteLine("Could not connect to session update endpoint: " + ex.ToString());
        return;
    }

    while (ws.State == WebSocketState.Open)
    {
        var (disposable, message, messageType) = await WebSocketReceiver.ReceiveAll(ws, ct);

        if (messageType == WebSocketMessageType.Close)
        {
            await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, null, ct);
            Console.WriteLine("Session update connection was closed");
        }
        else
        {
            try
            {
                string body = Encoding.UTF8.GetString(message.Span); // For debugging
                var scn = JsonSerializer.Deserialize<VsSessionChangeNotification>(message.Span, jsonSerializerOpts);
                if (scn is null)
                {
                    Console.WriteLine("Unexpected null notification message");
                    continue;
                }

                Console.WriteLine(scn.ToString());
                if (scn.NotificationType == NotificationType.SessionTerminated)
                {
                    Console.WriteLine("The run session ended.");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error while receiving session notification: {ex.ToString()}");
                return;
            }
            finally
            {
                disposable.Dispose();
            }
        }
    }
};

rootCommand.SetHandler(async (serverAddress) =>
{
    HttpClient client = new HttpClient();
    client.BaseAddress = new Uri($"http://{serverAddress}");

    var sr = new VsSessionRequest()
    {
        ProjectPath = "/code/myapp/src/service1/service1.csproj",
        Debug = true,
    };
    
    sr.Environment.Add(new EnvVar()
    {
        Name = "REDIS_SERVICE_HOST",
        Value = "localhost"
    });
    sr.Environment.Add(new EnvVar()
    {
        Name = "REDIS_SERVICE_PORT",
        Value = "6379"
    });

    sr.Arguments.Add("--verbosity=2");

    var response = await client.PutAsJsonAsync("/run_session", sr, jsonSerializerOpts, CancellationToken.None);
    if (!response.IsSuccessStatusCode)
    {
        Console.WriteLine($"Session could not be started: {response.ToString()}");
        return;
    }


    Console.WriteLine($"Session created successfully, id={response.Headers.Location}");

    await listenForSessionUpdates(serverAddress, CancellationToken.None);

}, serverAddressOption);

rootCommand.Invoke(args);
