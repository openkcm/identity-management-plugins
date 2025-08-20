//nolint:forbidigo,cyclop,funlen
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
	"github.com/openkcm/identity-management-plugins/pkg/utils/tlsconfig"
)

const usage = `Script to test SCIM API calls.
Usage: scimclient [options]
Options:
	--action	Action to perform (GetUser, ListUsers, GetGroup, ListGroups) (Required)
	--host		The SCIM server host (Required)
	--clientID	Client ID for authentication (Required)
	--clientSecret  Client secret value (if using secret auth)
	--certPath      Path to the client certificate file (if using cert-based auth)
	--keyPath       Path to the client private key file (if using cert-based auth)
	--useHTTPPost	Use HTTP POST to /.search endpoint instead of GET for listing users/groups
	--id		ID of the user or group to retrieve
	--cursor	Cursor for pagination
	--count	Limit for pagination
	--displayName	Search for groups/users by DisplayName attribute
`

const defaultCount = 100

func main() {
	log.SetOutput(os.Stdout)
	slog.SetLogLoggerLevel(slog.LevelDebug)

	var (
		action, host, clientID, clientSecret, certPath, keyPath, id, cursor, displayName string
		useHTTPPost                                                                      bool
		count                                                                            int
	)

	flag.StringVar(&action, "action", "", "Action to perform (GetUser, ListUsers, GetGroup, ListGroups)")
	flag.StringVar(&host, "host", "", "SCIM server host")
	flag.StringVar(&clientID, "clientID", "", "Client ID")
	flag.StringVar(&clientSecret, "clientSecret", "", "Client Secret")
	flag.StringVar(&certPath, "certPath", "", "Client Certificate Path")
	flag.StringVar(&keyPath, "keyPath", "", "Client Private Key Path")
	flag.StringVar(&id, "id", "", "ID of the user or group to retrieve")
	flag.StringVar(&cursor, "cursor", "", "Cursor for pagination")
	flag.StringVar(&displayName, "displayName", "", "Search for groups/users by DisplayName attribute")
	flag.IntVar(&count, "count", defaultCount, "Limit for pagination")
	flag.BoolVar(&useHTTPPost, "useHTTPPost", false,
		"Use HTTP POST to /.search endpoint instead of GET for listing users/groups")

	flag.Parse()

	if action == "" || host == "" || clientID == "" {
		fmt.Print(usage)
		os.Exit(1)
	}

	var (
		tlsConfig *tls.Config
		err       error
	)

	ctx := context.Background()

	if certPath != "" && keyPath != "" {
		tlsConfig, err = tlsconfig.NewTLSConfig(tlsconfig.WithCertAndKey(certPath, keyPath))
		if err != nil {
			fmt.Println("Error creating TLS config:", err.Error())
			os.Exit(1)
		}
	}

	client, err := scim.NewClient(ctx,
		scim.Params{
			Common: scim.Common{
				Host:         host,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			},
			TLS: tlsConfig,
		},
	)
	if err != nil {
		fmt.Println("Error creating SCIM client:", err.Error())
		os.Exit(1)
	}

	switch action {
	case "GetUser":
		getUser(ctx, client, id)
	case "ListUsers":
		listUsers(ctx, client, useHTTPPost, cursor, count, displayName)
	case "GetGroup":
		getGroup(ctx, client, id)
	case "ListGroups":
		listGroups(ctx, client, useHTTPPost, cursor, count, displayName)
	default:
		fmt.Println("Invalid action. Supported actions are: GetUser, ListUsers, GetGroup, ListGroups")
		os.Exit(1)
	}
}

func getUser(ctx context.Context, client *scim.Client, id string) {
	user, err := client.GetUser(ctx, id)
	if err != nil {
		fmt.Println("Error getting user:", err.Error())
		os.Exit(1)
	}

	fmt.Println("Found User:", user.UserName)
}

func listUsers(ctx context.Context,
	client *scim.Client,
	useHTTPPost bool,
	cursor string,
	count int,
	displayName string,
) {
	var filter scim.FilterExpression
	if displayName != "" {
		filter = scim.FilterComparison{
			Attribute: "displayName",
			Operator:  scim.FilterOperatorEqual,
			Value:     displayName,
		}
	} else {
		filter = scim.NullFilterExpression{}
	}

	users, err := client.ListUsers(ctx, useHTTPPost, filter, &cursor, &count)
	if err != nil {
		fmt.Println("Error listing users:", err.Error())
		os.Exit(1)
	}

	fmt.Println("Found Users:")

	for _, user := range users.Resources {
		fmt.Println(user.UserName)
	}
}

func getGroup(ctx context.Context, client *scim.Client, id string) {
	if id == "" {
		fmt.Println("ID is required for GetGroup action")
		os.Exit(1)
	}

	group, err := client.GetGroup(ctx, id)
	if err != nil {
		fmt.Println("Error getting group:", err.Error())
		os.Exit(1)
	}

	fmt.Println("Found Group:", group.DisplayName)
}

func listGroups(
	ctx context.Context,
	client *scim.Client,
	useHTTPPost bool,
	cursor string,
	count int,
	displayName string,
) {
	var filter scim.FilterExpression
	if displayName != "" {
		filter = scim.FilterComparison{
			Attribute: "displayName",
			Operator:  scim.FilterOperatorEqual,
			Value:     displayName,
		}
	} else {
		filter = scim.NullFilterExpression{}
	}

	groups, err := client.ListGroups(ctx, useHTTPPost, filter, &cursor, &count)
	if err != nil {
		fmt.Println("Error listing groups:", err.Error())
		os.Exit(1)
	}

	fmt.Println("Found Groups:")

	for _, group := range groups.Resources {
		fmt.Println(group.DisplayName)
	}
}
