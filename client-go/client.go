package main

import (
	"bytes"
	"context"
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

var serverAddress string
var 

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

	req, err := http.NewRequest("GET", "http://"+serverAddress+"/server_info", nil)
	if err != nil {
		return fmt.Errorf("Error creating server info request: %w", err)
	}
	// In real life we would send an 

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

	req, err := http.NewRequest("PUT", "http://"+serverAddress+"/run_session", bytes.NewBuffer(vsrBody))
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

	socket, _, err := websocket.DefaultDialer.Dial("ws://"+serverAddress+"/run_session/notify", nil)
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
			var scn VsSessionChangeNotification
			err = json.Unmarshal(msg, &scn)
			if err != nil {
				return fmt.Errorf("Error parsing session update: %w", err)
			}

			fmt.Println(scn.ToString())
			if scn.NotificationType == NotificationTypeSessionTerminated {
				fmt.Println("Session terminated")
				return nil
			}
		default:
			return fmt.Errorf("Unexpected message type received from session update endpoint: %d", msgType)
		}
	}
}
