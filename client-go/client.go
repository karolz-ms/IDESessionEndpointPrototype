package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	serverAddress        string
	payloadEncryptionKey []byte
	payloadSigningKey    []byte
	aesAlg               cipher.Block
)

const (
	payloadEncryptionKeyEnvVar = "DEBUG_SESSION_PAYLOAD_ENCRYPTION_KEY"
	payloadSigningKeyEnvVar    = "DEBUG_SESSION_PAYLOAD_SIGNING_KEY"
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
	err := initCrypto()
	if err != nil {
		return err
	}

	client := http.Client{}

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

	vsrBody, err = protectIfNecessary(vsrBody)
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
			var basicNotification ideSessionNotificationBase
			err = json.Unmarshal(msg, &basicNotification)
			if err != nil {
				return fmt.Errorf("Error parsing session update: %w", err)
			}

			if basicNotification.NotificationType == notificationTypeProtected {
				var protectedNotification ideSessionProtectedNotification
				err = json.Unmarshal(msg, &protectedNotification)
				if err != nil {
					return fmt.Errorf("Error parsing protected notification: %w", err)
				}

				decryptedData, err := protectedNotification.Data.Decrypt()
				if err != nil {
					return fmt.Errorf("Error decrypting protected notification: %w", err)
				}

				err = json.Unmarshal(decryptedData, &basicNotification)
				if err != nil {
					return fmt.Errorf("Error parsing decrypted notification: %w", err)
				}
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

func initCrypto() error {
	if os.Getenv(payloadEncryptionKeyEnvVar) != "" {
		key, err := base64.StdEncoding.DecodeString(os.Getenv(payloadEncryptionKeyEnvVar))
		if err != nil {
			return fmt.Errorf("Error decoding %s: %w", payloadEncryptionKeyEnvVar, err)
		}

		payloadEncryptionKey = key
	}
	if os.Getenv(payloadSigningKeyEnvVar) != "" {
		key, err := base64.StdEncoding.DecodeString(os.Getenv(payloadSigningKeyEnvVar))
		if err != nil {
			return fmt.Errorf("Error decoding %s: %w", payloadSigningKeyEnvVar, err)
		}

		payloadEncryptionKey = key
	}

	var cryptoErr error
	aesAlg, cryptoErr = aes.NewCipher(payloadEncryptionKey)
	if cryptoErr != nil {
		return fmt.Errorf("Error creating AES cipher: %w", cryptoErr)
	}

	return nil
}

func protectIfNecessary(data []byte) ([]byte, error) {
	if len(payloadEncryptionKey) == 0 {
		return data, nil
	}

	paddedData, err := Pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	ivAndCiphertext := make([]byte, aes.BlockSize+len(paddedData))
	iv := ivAndCiphertext[:aes.BlockSize]
	ciphertext := ivAndCiphertext[aes.BlockSize:]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("Error generating IV: %w", err)
	}

	encrypter := cipher.NewCBCEncrypter(aesAlg, iv)
	encrypter.CryptBlocks(ciphertext, paddedData)

	hmacSha256 := hmac.New(sha256.New, payloadSigningKey)
	authenticationTag := hmacSha256.Sum(nil)

	ep := encryptedPayload{
		Ciphertext:           base64.StdEncoding.EncodeToString(ciphertext),
		InitializationVector: base64.StdEncoding.EncodeToString(iv),
		AuthenticationTag:    base64.StdEncoding.EncodeToString(authenticationTag),
	}

	return json.Marshal(ep)
}
