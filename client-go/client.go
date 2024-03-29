package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

func main() {
	ctx := getSignalContext()

	clientCmd := newRootCommand()

	err := clientCmd.ExecuteContext(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func getSignalContext() context.Context {
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-shutdownChan
		cancel()
	}()
	return ctx
}

var (
	serverAddress string
)

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "client-go",
		Short: "Runs a sample client for Visual Studio run session endpoint",
		RunE:  runClient,
		Args:  cobra.NoArgs,
	}

	rootCmd.Flags().StringVarP(&serverAddress, "server", "s", "", "Address of the server to connect to")
	err := rootCmd.MarkFlagRequired("server")
	if err != nil {
		panic(err)
	}

	return rootCmd
}

func runClient(cmd *cobra.Command, _ []string) error {
	client := http.Client{}
	wsDialer := websocket.DefaultDialer
	uriScheme := "http"
	webSocketScheme := "ws"
	var certBytes []byte
	var err error

	serverCertEncodedBytes := os.Getenv("DEBUG_SESSION_SERVER_CERT")
	if serverCertEncodedBytes != "" {
		certBytes, err = base64.StdEncoding.AppendDecode(nil, []byte(serverCertEncodedBytes))
		if err != nil {
			return fmt.Errorf("Error reading server certificate: %w", err)
		}
	}

	serverCertFilePath := os.Getenv("DEBUG_SESSION_SERVER_CERT_FILE")
	if serverCertFilePath != "" {
		certBytes, err = os.ReadFile(serverCertFilePath)
		if err != nil {
			return fmt.Errorf("Error reading server certificate file: %w", err)
		}
	}

	if len(certBytes) > 0 {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("Error parsing server certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AddCert(cert)
		tlsConfig := &tls.Config{
			RootCAs: caCertPool,
		}
		client = http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
		wsDialer = &websocket.Dialer{
			TLSClientConfig: tlsConfig,
		}
		uriScheme = "https"
		webSocketScheme = "wss"
	}

	vsr := VsSessionRequest{
		ProjectPath: "/code/myap/src/service1/service1.csproj",
		Debug:       true,
	}
	vsr.Env = append(vsr.Env, EnvVar{Name: "REDIS_SERVICE_HOST", Value: "localhost"})
	vsr.Env = append(vsr.Env, EnvVar{Name: "REDIS_SERVICE_PORT", Value: "6379"})
	vsr.Arguments = append(vsr.Arguments, "--verbosity=2")
	vsrBody, err := json.Marshal(vsr)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"PUT",
		fmt.Sprintf("%s://%s/run_session", uriScheme, serverAddress),
		bytes.NewBuffer(vsrBody),
	)
	if err != nil {
		return fmt.Errorf("Error creating new session request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error sending new session request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body) // Best effort
		return fmt.Errorf("New session could not be started: %s %s", resp.Status, respBody)
	}

	fmt.Println("New session started successfully")

	socket, _, err := wsDialer.Dial(fmt.Sprintf("%s://%s/run_session/notify", webSocketScheme, serverAddress), nil)
	if err != nil {
		return fmt.Errorf("Error connecting to session update endpoint: %w", err)
	}
	defer socket.Close()

	for {
		msgType, msg, err := socket.ReadMessage()
		if err != nil {
			return fmt.Errorf("Error reading session update: %w", err)
		}

		switch msgType {
		case websocket.CloseMessage:
			fmt.Println("Session update connection closed")
			return nil
		case websocket.TextMessage:
			var basicNotification ideSessionNotificationBase
			err = json.Unmarshal(msg, &basicNotification)
			if err != nil {
				return fmt.Errorf("Error parsing session update: %w", err)
			}

			fmt.Println(basicNotification.String())
			if basicNotification.NotificationType == notificationTypeSessionTerminated {
				fmt.Println("Session terminated")
				return nil
			}

			if basicNotification.NotificationType == notificationTypeServiceLogs {
				var logNotification ideSessionLogNotification
				err = json.Unmarshal(msg, &logNotification)
				if err != nil {
					return fmt.Errorf("Error parsing log notification: %w", err)
				}

				var logSource string
				if logNotification.IsStdErr {
					logSource = "stderr"
				} else {
					logSource = "stdout"
				}
				fmt.Printf("Log (%s): %s\n", logSource, logNotification.LogMessage)
			}
		default:
			return fmt.Errorf("Unexpected message type received from session update endpoint: %d", msgType)
		}
	}
}
