// Package awsstore implements package store with the AWS SDK.
package awsstore

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// Options configure the AWS clients.
type Options struct {
	// TestEndpoint points the clients at a local AWS emulator and makes them
	// use fake credentials, ignoring any real ones. Test mode only.
	TestEndpoint string
	// SSMKMSKeyID is the KMS key for new SecureString parameters; empty uses
	// the AWS managed key.
	SSMKMSKeyID string
}

// New creates the stores. Outside test mode it uses the default AWS
// credential chain (IRSA or Pod Identity in Kubernetes).
func New(ctx context.Context, opts Options) (*Parameters, *Secrets, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRetryMode(aws.RetryModeAdaptive),
		awsconfig.WithRetryMaxAttempts(5),
	}
	if opts.TestEndpoint != "" {
		loadOpts = append(loadOpts,
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
		)
		if os.Getenv("AWS_REGION") == "" {
			loadOpts = append(loadOpts, awsconfig.WithRegion("eu-west-1"))
		}
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("load AWS config: %w", err)
	}

	ssmClient := ssm.NewFromConfig(cfg, func(o *ssm.Options) {
		if opts.TestEndpoint != "" {
			o.BaseEndpoint = aws.String(opts.TestEndpoint)
		}
	})
	secretsClient := secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		if opts.TestEndpoint != "" {
			o.BaseEndpoint = aws.String(opts.TestEndpoint)
		}
	})

	return &Parameters{client: ssmClient, kmsKeyID: opts.SSMKMSKeyID},
		&Secrets{client: secretsClient},
		nil
}

func timePtr(t *time.Time) *time.Time { return t }

func timeValue(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
