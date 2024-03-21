# IDE Session endpoint prototyping

## How to run the prototype

1. Run (F5) the VsSessionServer project.
2. As part of its startup sequence, VsSessionServer will output the path to public key certificate. Set the `DEBUG_SESSION_SERVER_CERT_FILE` environment variable to that path.
3. Change current folder to `client-go` folder and do `make run`.
