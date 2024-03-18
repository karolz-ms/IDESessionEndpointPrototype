# IDE Session endpoint prototyping

## To try out encrypted communication

1. Make sure that command line arguments for the VSSessionServer project contains `--payloadProtection` option. This can be set via `Properties/launchSettings.json` file inside the project folder.
2. Run (F5) the VsSessionServer project.
3. As part of its startup sequence, VsSessionServer will output the payload encryption key value and payload signing key value. Use these two values to set `DEBUG_SESSION_PAYLOAD_ENCRYPTION_KEY` and `DEBUG_SESSION_PAYLOAD_SIGNING_KEY`, respectively.
4. Change current folder to `client-go` folder and do `make run`.
 
