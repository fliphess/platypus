package awsstore

import (
	"context"
	"maps"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"platypus/internal/sensitive"
	"platypus/internal/store"
)

// Secrets implements store.Secrets for AWS Secrets Manager.
type Secrets struct {
	client *secretsmanager.Client
}

var _ store.Secrets = (*Secrets)(nil)

func (s *Secrets) List(ctx context.Context, fn func(store.Secret) error) error {
	pages := secretsmanager.NewListSecretsPaginator(s.client, &secretsmanager.ListSecretsInput{
		MaxResults:             aws.Int32(100),
		IncludePlannedDeletion: aws.Bool(true),
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return translate("list secrets", err)
		}
		for _, entry := range page.SecretList {
			secret := store.Secret{
				Name:             aws.ToString(entry.Name),
				ARN:              aws.ToString(entry.ARN),
				Description:      aws.ToString(entry.Description),
				KMSKeyID:         aws.ToString(entry.KmsKeyId),
				CurrentVersionID: currentVersion(entry.SecretVersionsToStages),
				LastChanged:      timeValue(entry.LastChangedDate),
				RotationEnabled:  aws.ToBool(entry.RotationEnabled),
				DeletedDate:      timePtr(entry.DeletedDate),
				Tags:             secretTagMap(entry.Tags),
			}
			if err := fn(secret); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Secrets) Describe(ctx context.Context, name string) (store.Secret, error) {
	out, err := s.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(name)})
	if err != nil {
		return store.Secret{}, translate("describe secret", err)
	}
	return store.Secret{
		Name:             aws.ToString(out.Name),
		ARN:              aws.ToString(out.ARN),
		Description:      aws.ToString(out.Description),
		KMSKeyID:         aws.ToString(out.KmsKeyId),
		CurrentVersionID: currentVersion(out.VersionIdsToStages),
		LastChanged:      timeValue(out.LastChangedDate),
		RotationEnabled:  aws.ToBool(out.RotationEnabled),
		DeletedDate:      timePtr(out.DeletedDate),
		Tags:             secretTagMap(out.Tags),
	}, nil
}

// Undelete cancels a scheduled deletion.
func (s *Secrets) Undelete(ctx context.Context, name string) error {
	if _, err := s.client.RestoreSecret(ctx, &secretsmanager.RestoreSecretInput{SecretId: aws.String(name)}); err != nil {
		return translate("restore secret", err)
	}
	return nil
}

func (s *Secrets) Value(ctx context.Context, name, versionID string) (sensitive.Value, error) {
	input := &secretsmanager.GetSecretValueInput{SecretId: aws.String(name)}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	out, err := s.client.GetSecretValue(ctx, input)
	if err != nil {
		return sensitive.Value{}, translate("get secret value", err)
	}
	if out.SecretString == nil {
		return sensitive.Value{}, store.ErrBinaryValue
	}
	return sensitive.New(*out.SecretString), nil
}

func (s *Secrets) Versions(ctx context.Context, name string) ([]store.SecretVersion, error) {
	pages := secretsmanager.NewListSecretVersionIdsPaginator(s.client, &secretsmanager.ListSecretVersionIdsInput{
		SecretId:          aws.String(name),
		IncludeDeprecated: aws.Bool(false),
	})
	var versions []store.SecretVersion
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, translate("list secret versions", err)
		}
		for _, v := range page.Versions {
			versions = append(versions, store.SecretVersion{
				ID:      aws.ToString(v.VersionId),
				Stages:  v.VersionStages,
				Created: timeValue(v.CreatedDate),
			})
		}
	}
	slices.SortFunc(versions, func(a, b store.SecretVersion) int { return b.Created.Compare(a.Created) })
	return versions, nil
}

func (s *Secrets) Create(ctx context.Context, ns store.NewSecret) (store.Secret, error) {
	input := &secretsmanager.CreateSecretInput{
		Name:         aws.String(ns.Name),
		SecretString: aws.String(ns.Value.Reveal()),
		Tags:         secretTags(ns.Tags),
	}
	if ns.Description != "" {
		input.Description = aws.String(ns.Description)
	}
	if _, err := s.client.CreateSecret(ctx, input); err != nil {
		return store.Secret{}, translate("create secret", err, ns.Value)
	}
	return s.Describe(ctx, ns.Name)
}

// PutValue checks the expected version first. Secrets Manager has no
// conditional write either; see Parameters.Update.
func (s *Secrets) PutValue(ctx context.Context, name string, value sensitive.Value, expectVersionID string) (store.Secret, error) {
	current, err := s.Describe(ctx, name)
	if err != nil {
		return store.Secret{}, err
	}
	if current.CurrentVersionID != expectVersionID {
		return store.Secret{}, store.ErrConflict
	}
	_, err = s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(name),
		SecretString: aws.String(value.Reveal()),
	})
	if err != nil {
		return store.Secret{}, translate("put secret value", err, value)
	}
	return s.Describe(ctx, name)
}

// UpdateDescription checks the expected version first, like PutValue.
func (s *Secrets) UpdateDescription(ctx context.Context, name, description, expectVersionID string) error {
	current, err := s.Describe(ctx, name)
	if err != nil {
		return err
	}
	if current.CurrentVersionID != expectVersionID {
		return store.ErrConflict
	}
	_, err = s.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
		SecretId:    aws.String(name),
		Description: aws.String(description),
	})
	return translate("update secret description", err)
}

func (s *Secrets) Restore(ctx context.Context, name, versionID, expectVersionID string) error {
	current, err := s.Describe(ctx, name)
	if err != nil {
		return err
	}
	if current.CurrentVersionID != expectVersionID {
		return store.ErrConflict
	}
	if versionID == current.CurrentVersionID {
		return nil
	}
	_, err = s.client.UpdateSecretVersionStage(ctx, &secretsmanager.UpdateSecretVersionStageInput{
		SecretId:            aws.String(name),
		VersionStage:        aws.String(store.StageCurrent),
		MoveToVersionId:     aws.String(versionID),
		RemoveFromVersionId: aws.String(current.CurrentVersionID),
	})
	return translate("restore secret version", err)
}

func (s *Secrets) CheckAccess(ctx context.Context, name string) error {
	_, err := s.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(name)})
	return translate("check secret access", err)
}

func currentVersion(versionsToStages map[string][]string) string {
	for id, stages := range versionsToStages {
		if slices.Contains(stages, store.StageCurrent) {
			return id
		}
	}
	return ""
}

func secretTagMap(tags []types.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return out
}

func secretTags(tags map[string]string) []types.Tag {
	var out []types.Tag
	for _, key := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, types.Tag{Key: aws.String(key), Value: aws.String(tags[key])})
	}
	return out
}
