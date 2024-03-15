using Microsoft.AspNetCore.Builder;
using VsSessionServer;

var builder = WebApplication.CreateSlimBuilder(args);

var app = builder.Build();
var encryptSensitivePayloads = args.Length > 1 && args[1] == "--encryptSensitivePayloads;";
var sessionServer = new Server(encryptSensitivePayloads);

app.MapGet("/", () => "Visual Studio run session server");

var runSessionApi = app.MapGroup("/run_session");
runSessionApi.MapPut("/", sessionServer.SessionPut);
runSessionApi.Map("/notify", sessionServer.SessionNotify);

app.UseWebSockets();

app.Run();

