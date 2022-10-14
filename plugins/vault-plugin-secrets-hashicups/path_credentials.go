package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCredentials extends the Vault API with a `/creds`
// endpoint for a role. You can choose whether
// or not certain attributes should be displayed,
// required, and named.
func pathCredentials(b *myBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks:       map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredentialsRead,
			logical.UpdateOperation: b.pathCredentialsRead,
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

// It creates the token based on the username in the role entry passed to the creds endpoint
func (b *myBackend) createToken(
	ctx context.Context,
	s logical.Storage,
	roleEntry *myRoleEntry) (*myToken, error) {

	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *myToken

	token, err = createToken(ctx, client, roleEntry.Username)
	if err != nil {
		return nil, fmt.Errorf("error creating HashiCups token: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating HashiCups token")
	}

	return token, nil
}

// The method creates the My token and maps it to a response for the secrets engine backend to return.
// It also sets the time to live (TTL) and maximum TTL for the secret.
func (b *myBackend) createUserCreds(
	ctx context.Context,
	req *logical.Request,
	role *myRoleEntry) (*logical.Response, error) {

	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(myTokenType).Response(map[string]interface{}{
		"token":    token.Token,
		"token_id": token.TokenID,
		"user_id":  token.UserID,
		"username": token.Username,
	}, map[string]interface{}{
		"token": token.Token,
		"role":  role.Username,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

// The method verifies the role exists for the secrets engine and creates a new HashiCups token based on the role entry.
func (b *myBackend) pathCredentialsRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createUserCreds(ctx, req, roleEntry)
}

const pathCredentialsHelpSyn = `
Generate a My API token from a specific Vault role.
`

const pathCredentialsHelpDesc = `
This path generates a My API user tokens
based on a particular role. A role can only represent a user token,
since My doesn't have other types of tokens.
`
