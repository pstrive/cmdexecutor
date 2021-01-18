/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/spf13/cobra"
)

const (
	TerminalColorRed   = "0x1B[0;40;31m%s0x1B[0m\n"
	TerminalColorGreen = "0x1B0;40;32m%s0x1B[0m\n"
)

var cmdExecutor *CmdExecutor

type CmdExecutor struct {
	Host        string
	Port        int32
	User        string
	Passwd      string
	AuthType    string
	Timeout     int64
	Command     string
	Concurrency int64
	FilePath    string
	client      *ssh.Client
}

func (n *CmdExecutor) validate() error {
	if len(n.Host) == 0 && len(n.FilePath) == 0 {
		return fmt.Errorf("host and filepath can't be null")
	}

	if n.AuthType == AuthTypePassword && len(n.Passwd) == 0 {
		return fmt.Errorf("password can't be null when auth type is password")
	}

	if len(n.Command) == 0 {
		return fmt.Errorf("command can't be null")
	}

	return nil
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cmdexecutor",
	Short: "command executor is a tool to run command on hosts",
	Long:  "command executor is a tool to run command on hosts",
	Run: func(cmd *cobra.Command, args []string) {
		if help, _ := cmd.Flags().GetBool("help"); help {
			_ = cmd.Help()
			os.Exit(0)
		}

		if cmd.Flags().NFlag() == 0 {
			_ = cmd.Help()
			os.Exit(0)
		}

		err := cmdExecutor.validate()
		if err != nil {
			panic(err)
		}

		hosts := []string{}
		result := map[string]map[string]string{
			"success": map[string]string{},
			"failed":  map[string]string{},
		}
		lock := &sync.RWMutex{}
		sem := make(chan struct{}, cmdExecutor.Concurrency)
		wg := &sync.WaitGroup{}

		if len(cmdExecutor.FilePath) > 0 {
			f, err := os.Open(cmdExecutor.FilePath)
			if err != nil {
				panic(err)
			}

			bs, err := ioutil.ReadAll(f)
			if err != nil {
				panic(err)
			}

			hosts = strings.Split(string(bs), "\n")
		} else {
			hosts = append(hosts, cmdExecutor.Host)
		}

		for _, host := range hosts {
			host = strings.TrimSpace(host)
			if len(host) == 0 {
				continue
			}

			fmt.Println("start deal ", host)

			wg.Add(1)
			sem <- struct{}{}

			go func(host string) {
				defer func() {
					<-sem
					wg.Done()
				}()

				sshclient := SSHClient{
					Host:     host,
					Port:     cmdExecutor.Port,
					User:     cmdExecutor.User,
					Passwd:   cmdExecutor.Passwd,
					AuthType: cmdExecutor.AuthType,
					Timeout:  cmdExecutor.Timeout,
					Command:  cmdExecutor.Command,
				}

				err := sshclient.connect()
				if err != nil {
					result["failed"][host] = err.Error()
					return
				}

				stdout, err := sshclient.do()

				lock.Lock()
				defer lock.Unlock()

				if err != nil {
					result["failed"][host] = err.Error()
					return
				}

				result["success"][host] = stdout
			}(host)
		}

		wg.Wait()
		close(sem)

		fmt.Println("--------------result--------------")

		fmt.Printf("%-15s\t%-10s\t%-30s\n", "host", "status", "out/error")

		for host, out := range result["success"] {
			str := fmt.Sprintf("%-15s\t%-10s\t%-30s\n", host, "success", strings.TrimSpace(out))
			fmt.Printf(str)
			//fmt.Printf(TerminalColorGreen, str)
		}

		for host, out := range result["failed"] {
			str := fmt.Sprintf("%-15s\t%-10s\t%-30s\n", host, "failed", strings.TrimSpace(out))
			fmt.Printf(str)
			//fmt.Printf(TerminalColorRed, str)
		}
	},
}

func init() {
	cmdExecutor = &CmdExecutor{}

	rootCmd.Flags().StringVarP(&cmdExecutor.FilePath, "filepath", "f", "", "file path of ip list")
	rootCmd.Flags().StringVarP(&cmdExecutor.Host, "host", "H", "", "host to connect")
	rootCmd.Flags().Int32VarP(&cmdExecutor.Port, "port", "P", 22, "host port to connect")
	rootCmd.Flags().StringVarP(&cmdExecutor.User, "user", "u", "root", "user")
	rootCmd.Flags().StringVarP(&cmdExecutor.Passwd, "password", "p", "", "password")
	rootCmd.Flags().StringVarP(&cmdExecutor.AuthType, "authType", "t", AuthTypePassword, "auth type of ssh")
	rootCmd.Flags().StringVarP(&cmdExecutor.Command, "command", "c", "", "command to run")
	rootCmd.Flags().Int64VarP(&cmdExecutor.Timeout, "timeout", "T", 3, "timeout")
	rootCmd.Flags().Int64VarP(&cmdExecutor.Concurrency, "concurrency", "C", 1, "concurrency")
}

func main() {
	Execute()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// ssh lib
const (
	AuthTypePassword = "password"
	AuthTypeKey      = "key"
)

type SSHClient struct {
	Host     string
	Port     int32
	User     string
	Passwd   string
	AuthType string
	Timeout  int64
	Command  string
	client   *ssh.Client
}

func (c *SSHClient) connect() error {
	config := &ssh.ClientConfig{
		Config: ssh.Config{
			Rand:           nil,
			RekeyThreshold: 0,
			KeyExchanges:   nil,
			Ciphers:        nil,
			MACs:           nil,
		},
		User:              c.User,
		Auth:              []ssh.AuthMethod{ssh.Password(c.Passwd)},
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		BannerCallback:    nil,
		HostKeyAlgorithms: nil,
		Timeout:           time.Second * time.Duration(c.Timeout),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port), config)
	if err != nil {
		return err
	}

	c.client = client

	return nil
}

func (c *SSHClient) do() (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer func() {
		_ = session.Close()
	}()

	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(c.Command)

	stdOutStr, _ := ioutil.ReadAll(&stdout)
	errMsg, _ := ioutil.ReadAll(&stderr)
	if err != nil {
		return string(stdOutStr), fmt.Errorf(string(errMsg))
	}

	if len(string(errMsg)) > 0 {
		return string(stdOutStr), fmt.Errorf(string(errMsg))
	}

	return string(stdOutStr), nil
}

