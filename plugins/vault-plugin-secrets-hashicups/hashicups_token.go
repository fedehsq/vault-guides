package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	myTokenType = "my_token"
)

// myToken defines a secret for the my token
type myToken struct {
	// Generated when a user first signs up for HashiCups.
	UserID int `json:"user_id"`
	// Set by the user when they first sign up for HashiCups.
	Username string `json:"username"`
	//  A unique identifier for the token. The HashiCups API does not generate a token ID, so you must implement ID generation in the secrets engine properly test token revocation and renewal.
	TokenID string `json:"token_id"`
	//  JWT for the HashiCups API.
	Token string `json:"token"`
}

// hashiCupsToken defines a secret to store for a given role and how it should be revoked or renewed.
func (b *myBackend) myToken() *framework.Secret {
	return &framework.Secret{
		Type: myTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "My Token",
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

// Signing out from the HashiCups API invalidates the JWT and prevents someone from using it.
func deleteToken(
	ctx context.Context,
	c *myClient,
	token string) error {

	c.Client.Token = token
	err := c.SignOut()

	if err != nil {
		return nil
	}

	return nil
}

// tokenRevoke removes the token from the Vault storage API and calls the client to revoke the token
func (b *myBackend) tokenRevoke(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData) (*logical.Response, error) {

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	token := ""
	tokenRaw, ok := req.Secret.InternalData["token"]
	if ok {
		token, ok = tokenRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for token in secret internal data")
		}
	}

	if err := deleteToken(ctx, client, token); err != nil {
		return nil, fmt.Errorf("error revoking user token: %w", err)
	}
	return nil, nil
}

// tokenRenew calls the client to create a new token and stores it in the Vault storage API
func createToken(
	ctx context.Context,
	c *myClient,
	username string) (*myToken, error) {

	response, err := c.SignIn()
	if err != nil {
		return nil, fmt.Errorf("error creating HashiCups token: %w", err)
	}

	tokenID := uuid.New().String()

	return &myToken{
		UserID:   response.UserID,
		Username: username,
		TokenID:  tokenID,
		Token:    response.Token,
	}, nil
}

// Verify that a role exists in the secrets engine backend before HashiCups creates a token. 
// You also pass the secrets object as a response and reset the time to live (TTL) and maximum TTL for the role.
func (b *myBackend) tokenRenew(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData) (*logical.Response, error) {

	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
