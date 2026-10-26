package awsstore

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"platypus/internal/item"
	"platypus/internal/sensitive"
	"platypus/internal/store"
)

// Parameters implements store.Parameters for SSM Parameter Store.
type Parameters struct {
	client   *ssm.Client
	kmsKeyID string
}

var _ store.Parameters = (*Parameters)(nil)

func (p *Parameters) List(ctx context.Context, fn func(store.Parameter) error) error {
	pages := ssm.NewDescribeParametersPaginator(p.client, &ssm.DescribeParametersInput{
		MaxResults: aws.Int32(50),
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return translate("list parameters", err)
		}
		for _, meta := range page.Parameters {
			if err := fn(parameterFromMetadata(meta)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Parameters) Describe(ctx context.Context, name string) (store.Parameter, error) {
	out, err := p.client.DescribeParameters(ctx, &ssm.DescribeParametersInput{
		ParameterFilters: []types.ParameterStringFilter{
			{Key: aws.String("Name"), Option: aws.String("Equals"), Values: []string{name}},
		},
	})
	if err != nil {
		return store.Parameter{}, translate("describe parameter", err)
	}
	if len(out.Parameters) == 0 {
		return store.Parameter{}, store.ErrNotFound
	}
	return parameterFromMetadata(out.Parameters[0]), nil
}

func (p *Parameters) Tags(ctx context.Context, name string) (map[string]string, error) {
	out, err := p.client.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
		ResourceType: types.ResourceTypeForTaggingParameter,
		ResourceId:   aws.String(name),
	})
	if err != nil {
		return nil, translate("list parameter tags", err)
	}
	tags := make(map[string]string, len(out.TagList))
	for _, tag := range out.TagList {
		tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	return tags, nil
}

func (p *Parameters) Value(ctx context.Context, name string, version int64) (sensitive.Value, error) {
	selector := name
	if version > 0 {
		selector = fmt.Sprintf("%s:%d", name, version)
	}
	out, err := p.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(selector),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return sensitive.Value{}, translate("get parameter value", err)
	}
	return sensitive.New(aws.ToString(out.Parameter.Value)), nil
}

// History returns the versions without values. The SSM API sends values of
// String parameters along regardless; they are dropped here, unread.
func (p *Parameters) History(ctx context.Context, name string) ([]store.ParameterVersion, error) {
	pages := ssm.NewGetParameterHistoryPaginator(p.client, &ssm.GetParameterHistoryInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(false),
		MaxResults:     aws.Int32(50),
	})
	var versions []store.ParameterVersion
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, translate("get parameter history", err)
		}
		for _, h := range page.Parameters {
			versions = append(versions, store.ParameterVersion{
				Version:        h.Version,
				Type:           string(h.Type),
				Tier:           string(h.Tier),
				Description:    aws.ToString(h.Description),
				Labels:         h.Labels,
				LastModified:   timeValue(h.LastModifiedDate),
				LastModifiedBy: aws.ToString(h.LastModifiedUser),
			})
		}
	}
	// SSM returns the oldest version first.
	for i, j := 0, len(versions)-1; i < j; i, j = i+1, j-1 {
		versions[i], versions[j] = versions[j], versions[i]
	}
	return versions, nil
}

func (p *Parameters) Create(ctx context.Context, np store.NewParameter) (store.Parameter, error) {
	input := &ssm.PutParameterInput{
		Name:      aws.String(np.Name),
		Value:     aws.String(np.Value.Reveal()),
		Type:      types.ParameterType(np.Type),
		Tier:      types.ParameterTier(np.Tier),
		Overwrite: aws.Bool(false),
		Tags:      ssmTags(np.Tags),
	}
	if np.Description != "" {
		input.Description = aws.String(np.Description)
	}
	if np.Type == item.SSMTypeSecureString && p.kmsKeyID != "" {
		input.KeyId = aws.String(p.kmsKeyID)
	}

	if _, err := p.client.PutParameter(ctx, input); err != nil {
		return store.Parameter{}, translate("create parameter", err, np.Value)
	}
	return p.Describe(ctx, np.Name)
}

// Update checks the expected version first. SSM has no conditional write, so
// a change landing between the check and the write can't be detected; the
// window is a single round trip.
func (p *Parameters) Update(ctx context.Context, u store.ParameterUpdate) (store.Parameter, error) {
	current, err := p.Describe(ctx, u.Name)
	if err != nil {
		return store.Parameter{}, err
	}
	if current.Version != u.ExpectVersion {
		return store.Parameter{}, store.ErrConflict
	}

	input := &ssm.PutParameterInput{
		Name:      aws.String(u.Name),
		Value:     aws.String(u.Value.Reveal()),
		Type:      types.ParameterType(u.Type),
		Tier:      types.ParameterTier(u.Tier),
		Overwrite: aws.Bool(true),
	}
	if u.Description != "" {
		input.Description = aws.String(u.Description)
	}
	if u.Type == item.SSMTypeSecureString {
		// Keep the parameter's own key; only fall back to the configured one.
		switch {
		case current.KMSKeyID != "":
			input.KeyId = aws.String(current.KMSKeyID)
		case p.kmsKeyID != "":
			input.KeyId = aws.String(p.kmsKeyID)
		}
	}

	if _, err := p.client.PutParameter(ctx, input); err != nil {
		return store.Parameter{}, translate("update parameter", err, u.Value)
	}
	return p.Describe(ctx, u.Name)
}

func (p *Parameters) Write(ctx context.Context, name string, value sensitive.Value, description string) error {
	input := &ssm.PutParameterInput{
		Name:        aws.String(name),
		Value:       aws.String(value.Reveal()),
		Type:        types.ParameterTypeSecureString,
		Description: aws.String(description),
		Overwrite:   aws.Bool(true),
	}
	if p.kmsKeyID != "" {
		input.KeyId = aws.String(p.kmsKeyID)
	}
	_, err := p.client.PutParameter(ctx, input)
	return translate("write parameter", err, value)
}

// CheckAccess reads the parameter without decryption. For String parameters
// the response carries the value; it is discarded unread. A KMS key policy
// denying platypus only shows up on decryption: Value then returns
// ErrAccessDenied and the caller hides the item.
func (p *Parameters) CheckAccess(ctx context.Context, name string) error {
	_, err := p.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(false),
	})
	return translate("check parameter access", err)
}

func parameterFromMetadata(m types.ParameterMetadata) store.Parameter {
	return store.Parameter{
		Name:           aws.ToString(m.Name),
		Type:           string(m.Type),
		Tier:           string(m.Tier),
		DataType:       aws.ToString(m.DataType),
		Description:    aws.ToString(m.Description),
		KMSKeyID:       aws.ToString(m.KeyId),
		Version:        m.Version,
		LastModified:   timeValue(m.LastModifiedDate),
		LastModifiedBy: aws.ToString(m.LastModifiedUser),
	}
}

func ssmTags(tags map[string]string) []types.Tag {
	var out []types.Tag
	for _, key := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, types.Tag{Key: aws.String(key), Value: aws.String(tags[key])})
	}
	return out
}
