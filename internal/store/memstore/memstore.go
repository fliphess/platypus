// Package memstore implements package store in memory, for tests. It passes
// the same contract tests (package storetest) as the AWS implementation.
package memstore

import (
	"cmp"
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"platypus/internal/sensitive"
	"platypus/internal/store"
)

// access lets tests make items unreachable for platypus or binary.
type access struct {
	denied map[string]bool
	binary map[string]bool
}

func (a *access) check(name string) error {
	if a.denied[name] {
		return store.ErrAccessDenied
	}
	return nil
}

// Parameters is an in-memory store.Parameters.
type Parameters struct {
	mu     sync.Mutex
	params map[string]*parameter
	access access
	now    func() time.Time
}

type parameter struct {
	meta     store.Parameter
	tags     map[string]string
	versions []parameterVersion // oldest first
}

type parameterVersion struct {
	meta  store.ParameterVersion
	value sensitive.Value
}

var _ store.Parameters = (*Parameters)(nil)

// NewParameters returns an empty parameter store.
func NewParameters() *Parameters {
	return &Parameters{
		params: map[string]*parameter{},
		access: access{denied: map[string]bool{}, binary: map[string]bool{}},
		now:    time.Now,
	}
}

// Deny makes AWS deny platypus access to the named parameter.
func (p *Parameters) Deny(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.access.denied[name] = true
}

func (p *Parameters) List(_ context.Context, fn func(store.Parameter) error) error {
	p.mu.Lock()
	all := make([]store.Parameter, 0, len(p.params))
	for _, param := range p.params {
		all = append(all, param.meta)
	}
	p.mu.Unlock()

	slices.SortFunc(all, func(a, b store.Parameter) int { return cmp.Compare(a.Name, b.Name) })
	for _, param := range all {
		if err := fn(param); err != nil {
			return err
		}
	}
	return nil
}

func (p *Parameters) Describe(_ context.Context, name string) (store.Parameter, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	param, ok := p.params[name]
	if !ok {
		return store.Parameter{}, store.ErrNotFound
	}
	return param.meta, nil
}

func (p *Parameters) Tags(_ context.Context, name string) (map[string]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	param, ok := p.params[name]
	if !ok {
		return nil, store.ErrNotFound
	}
	return maps.Clone(param.tags), nil
}

func (p *Parameters) Value(_ context.Context, name string, version int64) (sensitive.Value, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	param, ok := p.params[name]
	if !ok {
		return sensitive.Value{}, store.ErrNotFound
	}
	if err := p.access.check(name); err != nil {
		return sensitive.Value{}, err
	}
	if version == 0 {
		version = param.meta.Version
	}
	for _, v := range param.versions {
		if v.meta.Version == version {
			return v.value, nil
		}
	}
	return sensitive.Value{}, store.ErrNotFound
}

func (p *Parameters) History(_ context.Context, name string) ([]store.ParameterVersion, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	param, ok := p.params[name]
	if !ok {
		return nil, store.ErrNotFound
	}
	history := make([]store.ParameterVersion, 0, len(param.versions))
	for i := len(param.versions) - 1; i >= 0; i-- {
		history = append(history, param.versions[i].meta)
	}
	return history, nil
}

func (p *Parameters) Create(_ context.Context, np store.NewParameter) (store.Parameter, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.params[np.Name]; exists {
		return store.Parameter{}, store.ErrAlreadyExists
	}
	param := &parameter{tags: maps.Clone(np.Tags)}
	if param.tags == nil {
		param.tags = map[string]string{}
	}
	p.params[np.Name] = param
	p.addVersion(param, np.Name, np.Value, np.Type, np.Tier, np.Description)
	return param.meta, nil
}

func (p *Parameters) Update(_ context.Context, u store.ParameterUpdate) (store.Parameter, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	param, ok := p.params[u.Name]
	if !ok {
		return store.Parameter{}, store.ErrNotFound
	}
	if param.meta.Version != u.ExpectVersion {
		return store.Parameter{}, store.ErrConflict
	}
	description := u.Description
	if description == "" {
		description = param.meta.Description
	}
	p.addVersion(param, u.Name, u.Value, u.Type, u.Tier, description)
	return param.meta, nil
}

func (p *Parameters) Write(_ context.Context, name string, value sensitive.Value, description string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	param, ok := p.params[name]
	if !ok {
		param = &parameter{tags: map[string]string{}}
		p.params[name] = param
	}
	p.addVersion(param, name, value, "SecureString", "Standard", description)
	return nil
}

func (p *Parameters) CheckAccess(_ context.Context, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.params[name]; !ok {
		return store.ErrNotFound
	}
	return p.access.check(name)
}

// addVersion appends a version; the caller holds the lock.
func (p *Parameters) addVersion(param *parameter, name string, value sensitive.Value, typ, tier, description string) {
	now := p.now()
	version := param.meta.Version + 1
	param.meta = store.Parameter{
		Name:           name,
		Type:           typ,
		Tier:           tier,
		DataType:       "text",
		Description:    description,
		Version:        version,
		LastModified:   now,
		LastModifiedBy: "arn:aws:iam::000000000000:role/platypus",
	}
	param.versions = append(param.versions, parameterVersion{
		meta: store.ParameterVersion{
			Version:        version,
			Type:           typ,
			Tier:           tier,
			Description:    description,
			LastModified:   now,
			LastModifiedBy: param.meta.LastModifiedBy,
		},
		value: value,
	})
}

// Secrets is an in-memory store.Secrets.
type Secrets struct {
	mu      sync.Mutex
	secrets map[string]*secret
	access  access
	now     func() time.Time
}

type secret struct {
	meta     store.Secret
	versions []secretVersion // oldest first
}

type secretVersion struct {
	meta  store.SecretVersion
	value sensitive.Value
}

var _ store.Secrets = (*Secrets)(nil)

// NewSecrets returns an empty secret store.
func NewSecrets() *Secrets {
	return &Secrets{
		secrets: map[string]*secret{},
		access:  access{denied: map[string]bool{}, binary: map[string]bool{}},
		now:     time.Now,
	}
}

// Deny makes AWS deny platypus access to the named secret.
func (s *Secrets) Deny(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.access.denied[name] = true
}

// MarkDeleted schedules the named secret for deletion (as AWS does), so
// tests can exercise the restore path.
func (s *Secrets) MarkDeleted(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[name]
	if !ok {
		return
	}
	deleted := s.now()
	sec.meta.DeletedDate = &deleted
}

func (s *Secrets) Undelete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[name]
	if !ok {
		return store.ErrNotFound
	}
	if err := s.access.check(name); err != nil {
		return err
	}
	if sec.meta.DeletedDate == nil {
		return store.ErrNotFound
	}
	sec.meta.DeletedDate = nil
	return nil
}

// MarkBinary makes the named secret hold a binary value.
func (s *Secrets) MarkBinary(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.access.binary[name] = true
}

func (s *Secrets) List(_ context.Context, fn func(store.Secret) error) error {
	s.mu.Lock()
	all := make([]store.Secret, 0, len(s.secrets))
	for _, sec := range s.secrets {
		all = append(all, cloneSecret(sec.meta))
	}
	s.mu.Unlock()

	slices.SortFunc(all, func(a, b store.Secret) int { return cmp.Compare(a.Name, b.Name) })
	for _, sec := range all {
		if err := fn(sec); err != nil {
			return err
		}
	}
	return nil
}

func (s *Secrets) Describe(_ context.Context, name string) (store.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[name]
	if !ok {
		return store.Secret{}, store.ErrNotFound
	}
	if err := s.access.check(name); err != nil {
		return store.Secret{}, err
	}
	return cloneSecret(sec.meta), nil
}

func (s *Secrets) Value(_ context.Context, name, versionID string) (sensitive.Value, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[name]
	if !ok {
		return sensitive.Value{}, store.ErrNotFound
	}
	if err := s.access.check(name); err != nil {
		return sensitive.Value{}, err
	}
	if sec.meta.DeletedDate != nil {
		return sensitive.Value{}, store.ErrNotFound
	}
	if s.access.binary[name] {
		return sensitive.Value{}, store.ErrBinaryValue
	}
	if versionID == "" {
		versionID = sec.meta.CurrentVersionID
	}
	for _, v := range sec.versions {
		if v.meta.ID == versionID {
			return v.value, nil
		}
	}
	return sensitive.Value{}, store.ErrNotFound
}

func (s *Secrets) Versions(_ context.Context, name string) ([]store.SecretVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[name]
	if !ok {
		return nil, store.ErrNotFound
	}
	var versions []store.SecretVersion
	for i := len(sec.versions) - 1; i >= 0; i-- {
		if v := sec.versions[i].meta; len(v.Stages) > 0 {
			versions = append(versions, store.SecretVersion{ID: v.ID, Stages: slices.Clone(v.Stages), Created: v.Created})
		}
	}
	return versions, nil
}

func (s *Secrets) Create(_ context.Context, ns store.NewSecret) (store.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.secrets[ns.Name]; exists {
		return store.Secret{}, store.ErrAlreadyExists
	}
	tags := maps.Clone(ns.Tags)
	if tags == nil {
		tags = map[string]string{}
	}
	sec := &secret{meta: store.Secret{
		Name:        ns.Name,
		ARN:         "arn:aws:secretsmanager:eu-west-1:000000000000:secret:" + ns.Name + "-abc123",
		Description: ns.Description,
		Tags:        tags,
	}}
	s.secrets[ns.Name] = sec
	s.addVersion(sec, ns.Value)
	return cloneSecret(sec.meta), nil
}

func (s *Secrets) PutValue(_ context.Context, name string, value sensitive.Value, expectVersionID string) (store.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[name]
	if !ok {
		return store.Secret{}, store.ErrNotFound
	}
	if sec.meta.CurrentVersionID != expectVersionID {
		return store.Secret{}, store.ErrConflict
	}
	s.addVersion(sec, value)
	return cloneSecret(sec.meta), nil
}

func (s *Secrets) UpdateDescription(_ context.Context, name, description, expectVersionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[name]
	if !ok {
		return store.ErrNotFound
	}
	if sec.meta.CurrentVersionID != expectVersionID {
		return store.ErrConflict
	}
	sec.meta.Description = description
	return nil
}

func (s *Secrets) Restore(_ context.Context, name, versionID, expectVersionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[name]
	if !ok {
		return store.ErrNotFound
	}
	if sec.meta.CurrentVersionID != expectVersionID {
		return store.ErrConflict
	}
	target := -1
	for i, v := range sec.versions {
		if v.meta.ID == versionID {
			target = i
		}
	}
	if target < 0 {
		return store.ErrNotFound
	}
	s.setCurrent(sec, target)
	return nil
}

func (s *Secrets) CheckAccess(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.secrets[name]; !ok {
		return store.ErrNotFound
	}
	return s.access.check(name)
}

// addVersion appends a version and makes it current; the caller holds the lock.
func (s *Secrets) addVersion(sec *secret, value sensitive.Value) {
	sec.versions = append(sec.versions, secretVersion{
		meta:  store.SecretVersion{ID: newVersionID(), Created: s.now()},
		value: value,
	})
	s.setCurrent(sec, len(sec.versions)-1)
}

// setCurrent moves AWSCURRENT to version i and AWSPREVIOUS to the version that
// was current, as Secrets Manager does.
func (s *Secrets) setCurrent(sec *secret, i int) {
	for j := range sec.versions {
		stages := sec.versions[j].meta.Stages
		stages = slices.DeleteFunc(stages, func(stage string) bool { return stage == store.StagePrevious })
		if slices.Contains(stages, store.StageCurrent) && j != i {
			stages = []string{store.StagePrevious}
		}
		sec.versions[j].meta.Stages = stages
	}
	sec.versions[i].meta.Stages = []string{store.StageCurrent}
	sec.meta.CurrentVersionID = sec.versions[i].meta.ID
	sec.meta.LastChanged = s.now()
}

func cloneSecret(sec store.Secret) store.Secret {
	sec.Tags = maps.Clone(sec.Tags)
	return sec
}

func newVersionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
