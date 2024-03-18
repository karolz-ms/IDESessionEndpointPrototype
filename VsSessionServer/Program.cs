using Microsoft.AspNetCore.Builder;
using VsSessionServer;

var builder = WebApplication.CreateSlimBuilder(args);

var app = builder.Build();
var payloadProtection = args.Length >= 1 && args[0] == "--payloadProtection";
var sessionServer = new Server(payloadProtection);

app.MapGet("/", () => "Visual Studio run session server");

var runSessionApi = app.MapGroup("/run_session");

// The cast is necessary, otherwise the result is ignored
// See https://learn.microsoft.com/en-us/aspnet/core/diagnostics/asp0016?view=aspnetcore-8.0 for details.
runSessionApi.MapPut("/", (System.Delegate) sessionServer.SessionPut);

runSessionApi.Map("/notify", sessionServer.SessionNotify);

app.UseWebSockets();

app.Run();

