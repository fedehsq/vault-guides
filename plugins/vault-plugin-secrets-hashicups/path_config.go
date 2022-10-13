package secretsengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

// myConfig includes the minimum configuration required to instantiate a new My client.
type myConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

// pathConfig extends the Vault API with a `/config` endpoint for the backend.
func pathConfig(b *myBackend) *framework.Path {
	return &framework.Path{
		// This backend supports the "config" endpoint to store the configuration.
		Pattern: "config",
		// Config fields are 'username', 'password', and 'url'.
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "The username to access My Product API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Username",
					Sensitive: false,
				},
			},
			"password": {
				Type:        framework.TypeString,
				Description: "The user's password to access My Product API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Password",
					Sensitive: true,
				},
			},
			"url": {
				Type:        framework.TypeString,
				Description: "The URL for the My Product API",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "URL",
					Sensitive: false,
				},
			},
		},
		// Read, write, update and delete operations are supported.
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *myBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*myConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(myConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}

// The method reads the configuration and outputs non-sensitive fields,
// specifically the My username and URL.
func (b *myBackend) pathConfigRead(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"username": config.Username,
			"url":      config.URL,
		},
	}, nil
}

// The method reads the configuration and outputs non-sensitive fields,
// specifically the My username and URL.
func (b *myBackend) pathConfigDelete(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)
	if err == nil {
		b.reset()
	}
	return nil, err
}

// The method accounts for specific logic, including:
// If the configuration does not exist and you need to update it,
// the handler throws an error.
// Verify you passed a username, URL, and password for the target API
// to the configuration using the GetOk method.
// You use GetOk to enforce required attributes during a CreateOperation.
// Write the new or updated configuration using Storage.Put.
// Reset the configuration so Vault picks up the new configuration.
func (b *myBackend) pathConfigWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(myConfig)
	}

	if username, ok := data.GetOk("username"); ok {
		config.Username = username.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing username in configuration")
	}

	if url, ok := data.GetOk("url"); ok {
		config.URL = url.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing url in configuration")
	}

	if password, ok := data.GetOk("password"); ok {
		config.Password = password.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing password in configuration")
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the My backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The My secret backend requires credentials for managing
JWTs issued to users working with the products API.

You must sign up with a username and password and
specify the My address for the products API
before using this secrets backend.
`
