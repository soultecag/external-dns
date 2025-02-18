/*
Copyright 2017 The Kubernetes Authors.

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

package uszipam

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"

	"github.com/stretchr/testify/require"
)

const defaultUszIpamPrefix = "/skydns/"

type fakeUSZ_IpamClient struct {
	services map[string]Service
}

func (c fakeUSZ_IpamClient) GetServices(prefix string) ([]*Service, error) {
	var result []*Service
	for key, value := range c.services {
		if strings.HasPrefix(key, prefix) {
			valueCopy := value
			valueCopy.Key = key
			result = append(result, &valueCopy)
		}
	}
	return result, nil
}

func (c fakeUSZ_IpamClient) SaveService(service *Service) error {
	c.services[service.Key] = *service
	return nil
}

func (c fakeUSZ_IpamClient) DeleteService(key string) error {
	delete(c.services, key)
	return nil
}

func TestUSZipamConfig(t *testing.T) {
	var tests = []struct {
		name    string
		input   map[string]string
		want    *Config
		wantErr bool
	}{
		{
			"default config - missing variables",
			map[string]string{},
			nil,
			true, // Expecting an error because required vars are missing
		},
		{
			"config with USZIPAM_API_BASE_URL",
			map[string]string{"USZIPAM_API_BASE_URL": "http://example.com:8080", "USZIPAM_API_KEY": "some-api-key"},
			&Config{
				APIBaseURL: "http://example.com:8080",
				APIKey:     "some-api-key",
			},
			false, // No error, as both required vars are present
		},
		{
			"config with missing API_KEY",
			map[string]string{"USZIPAM_API_BASE_URL": "http://example.com:8080"},
			nil,
			true, // Expecting an error because API_KEY is missing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables for this test case
			closer := envSetter(tt.input)
			defer t.Cleanup(closer)

			// Call NewConfig() to get the configuration
			cfg, err := NewConfig()

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				return // Skip further checks if we expect an error
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Compare the returned config with the expected config
			if !reflect.DeepEqual(cfg, tt.want) {
				t.Errorf("unexpected config. Got %v, want %v", cfg, tt.want)
			}
		})
	}
}

func envSetter(envs map[string]string) (closer func()) {
	originalEnvs := map[string]string{}

	for name, value := range envs {
		if originalValue, ok := os.LookupEnv(name); ok {
			originalEnvs[name] = originalValue
		}
		_ = os.Setenv(name, value)
	}

	return func() {
		for name := range envs {
			origValue, has := originalEnvs[name]
			if has {
				_ = os.Setenv(name, origValue)
			} else {
				_ = os.Unsetenv(name)
			}
		}
	}
}

func TestAServiceTranslation(t *testing.T) {
	expectedTarget := "1.2.3.4"
	expectedDNSName := "example.com"
	expectedRecordType := endpoint.RecordTypeA

	client := fakeUSZ_IpamClient{
		map[string]Service{
			"/skydns/com/example": {Host: expectedTarget},
		},
	}
	provider := uszIpamProvider{
		client:        client,
		uszIpamPrefix: defaultUszIpamPrefix,
	}
	endpoints, err := provider.Records(context.Background())
	require.NoError(t, err)
	if len(endpoints) != 1 {
		t.Fatalf("got unexpected number of endpoints: %d", len(endpoints))
	}
	if endpoints[0].DNSName != expectedDNSName {
		t.Errorf("got unexpected DNS name: %s != %s", endpoints[0].DNSName, expectedDNSName)
	}
	if endpoints[0].Targets[0] != expectedTarget {
		t.Errorf("got unexpected DNS target: %s != %s", endpoints[0].Targets[0], expectedTarget)
	}
	if endpoints[0].RecordType != expectedRecordType {
		t.Errorf("got unexpected DNS record type: %s != %s", endpoints[0].RecordType, expectedRecordType)
	}
}

func TestCNAMEServiceTranslation(t *testing.T) {
	expectedTarget := "example.net"
	expectedDNSName := "example.com"
	expectedRecordType := endpoint.RecordTypeCNAME

	client := fakeUSZ_IpamClient{
		map[string]Service{
			"/skydns/com/example": {Host: expectedTarget},
		},
	}
	provider := uszIpamProvider{
		client:        client,
		uszIpamPrefix: defaultUszIpamPrefix,
	}
	endpoints, err := provider.Records(context.Background())
	require.NoError(t, err)
	if len(endpoints) != 1 {
		t.Fatalf("got unexpected number of endpoints: %d", len(endpoints))
	}
	if endpoints[0].DNSName != expectedDNSName {
		t.Errorf("got unexpected DNS name: %s != %s", endpoints[0].DNSName, expectedDNSName)
	}
	if endpoints[0].Targets[0] != expectedTarget {
		t.Errorf("got unexpected DNS target: %s != %s", endpoints[0].Targets[0], expectedTarget)
	}
	if endpoints[0].RecordType != expectedRecordType {
		t.Errorf("got unexpected DNS record type: %s != %s", endpoints[0].RecordType, expectedRecordType)
	}
}

func TestTXTServiceTranslation(t *testing.T) {
	expectedTarget := "string"
	expectedDNSName := "example.com"
	expectedRecordType := endpoint.RecordTypeTXT

	client := fakeUSZ_IpamClient{
		map[string]Service{
			"/skydns/com/example": {Text: expectedTarget},
		},
	}
	provider := uszIpamProvider{
		client:        client,
		uszIpamPrefix: defaultUszIpamPrefix,
	}
	endpoints, err := provider.Records(context.Background())
	require.NoError(t, err)
	if len(endpoints) != 1 {
		t.Fatalf("got unexpected number of endpoints: %d", len(endpoints))
	}
	if endpoints[0].DNSName != expectedDNSName {
		t.Errorf("got unexpected DNS name: %s != %s", endpoints[0].DNSName, expectedDNSName)
	}
	if endpoints[0].Targets[0] != expectedTarget {
		t.Errorf("got unexpected DNS target: %s != %s", endpoints[0].Targets[0], expectedTarget)
	}
	if endpoints[0].RecordType != expectedRecordType {
		t.Errorf("got unexpected DNS record type: %s != %s", endpoints[0].RecordType, expectedRecordType)
	}
}

func TestAWithTXTServiceTranslation(t *testing.T) {
	expectedTargets := map[string]string{
		endpoint.RecordTypeA:   "1.2.3.4",
		endpoint.RecordTypeTXT: "string",
	}
	expectedDNSName := "example.com"

	client := fakeUSZ_IpamClient{
		map[string]Service{
			"/skydns/com/example": {Host: "1.2.3.4", Text: "string"},
		},
	}
	provider := uszIpamProvider{
		client:        client,
		uszIpamPrefix: defaultUszIpamPrefix,
	}
	endpoints, err := provider.Records(context.Background())
	require.NoError(t, err)
	if len(endpoints) != len(expectedTargets) {
		t.Fatalf("got unexpected number of endpoints: %d", len(endpoints))
	}

	for _, ep := range endpoints {
		expectedTarget := expectedTargets[ep.RecordType]
		if expectedTarget == "" {
			t.Errorf("got unexpected DNS record type: %s", ep.RecordType)
			continue
		}
		delete(expectedTargets, ep.RecordType)

		if ep.DNSName != expectedDNSName {
			t.Errorf("got unexpected DNS name: %s != %s", ep.DNSName, expectedDNSName)
		}

		if ep.Targets[0] != expectedTarget {
			t.Errorf("got unexpected DNS target: %s != %s", ep.Targets[0], expectedTarget)
		}
	}
}

func TestCNAMEWithTXTServiceTranslation(t *testing.T) {
	expectedTargets := map[string]string{
		endpoint.RecordTypeCNAME: "example.net",
		endpoint.RecordTypeTXT:   "string",
	}
	expectedDNSName := "example.com"

	client := fakeUSZ_IpamClient{
		map[string]Service{
			"/skydns/com/example": {Host: "example.net", Text: "string"},
		},
	}
	provider := uszIpamProvider{
		client:        client,
		uszIpamPrefix: defaultUszIpamPrefix,
	}
	endpoints, err := provider.Records(context.Background())
	require.NoError(t, err)
	if len(endpoints) != len(expectedTargets) {
		t.Fatalf("got unexpected number of endpoints: %d", len(endpoints))
	}

	for _, ep := range endpoints {
		expectedTarget := expectedTargets[ep.RecordType]
		if expectedTarget == "" {
			t.Errorf("got unexpected DNS record type: %s", ep.RecordType)
			continue
		}
		delete(expectedTargets, ep.RecordType)

		if ep.DNSName != expectedDNSName {
			t.Errorf("got unexpected DNS name: %s != %s", ep.DNSName, expectedDNSName)
		}

		if ep.Targets[0] != expectedTarget {
			t.Errorf("got unexpected DNS target: %s != %s", ep.Targets[0], expectedTarget)
		}
	}
}

func TestUszIpamApplyChanges(t *testing.T) {
	client := fakeUSZ_IpamClient{
		map[string]Service{},
	}
	uszipam := uszIpamProvider{
		client:        client,
		uszIpamPrefix: defaultUszIpamPrefix,
	}

	changes1 := &plan.Changes{
		Create: []*endpoint.Endpoint{
			endpoint.NewEndpoint("domain1.local", endpoint.RecordTypeA, "5.5.5.5"),
			endpoint.NewEndpoint("domain1.local", endpoint.RecordTypeTXT, "string1"),
			endpoint.NewEndpoint("domain2.local", endpoint.RecordTypeCNAME, "site.local"),
		},
	}
	err := uszipam.ApplyChanges(context.Background(), changes1)
	require.NoError(t, err)

	expectedServices1 := map[string][]*Service{
		"/skydns/local/domain1": {{Host: "5.5.5.5", Text: "string1"}},
		"/skydns/local/domain2": {{Host: "site.local"}},
	}
	validateServices(client.services, expectedServices1, t, 1)

	changes2 := &plan.Changes{
		Create: []*endpoint.Endpoint{
			endpoint.NewEndpoint("domain3.local", endpoint.RecordTypeA, "7.7.7.7"),
		},
		UpdateNew: []*endpoint.Endpoint{
			endpoint.NewEndpoint("domain1.local", "A", "6.6.6.6"),
		},
	}
	records, _ := uszipam.Records(context.Background())
	for _, ep := range records {
		if ep.DNSName == "domain1.local" {
			changes2.UpdateOld = append(changes2.UpdateOld, ep)
		}
	}
	err = applyServiceChanges(uszipam, changes2)
	require.NoError(t, err)

	expectedServices2 := map[string][]*Service{
		"/skydns/local/domain1": {{Host: "6.6.6.6", Text: "string1"}},
		"/skydns/local/domain2": {{Host: "site.local"}},
		"/skydns/local/domain3": {{Host: "7.7.7.7"}},
	}
	validateServices(client.services, expectedServices2, t, 2)

	changes3 := &plan.Changes{
		Delete: []*endpoint.Endpoint{
			endpoint.NewEndpoint("domain1.local", endpoint.RecordTypeA, "6.6.6.6"),
			endpoint.NewEndpoint("domain1.local", endpoint.RecordTypeTXT, "string"),
			endpoint.NewEndpoint("domain3.local", endpoint.RecordTypeA, "7.7.7.7"),
		},
	}

	err = applyServiceChanges(uszipam, changes3)
	require.NoError(t, err)

	expectedServices3 := map[string][]*Service{
		"/skydns/local/domain2": {{Host: "site.local"}},
	}
	validateServices(client.services, expectedServices3, t, 3)

	// Test for multiple A records for the same FQDN
	changes4 := &plan.Changes{
		Create: []*endpoint.Endpoint{
			endpoint.NewEndpoint("domain1.local", endpoint.RecordTypeA, "5.5.5.5"),
			endpoint.NewEndpoint("domain1.local", endpoint.RecordTypeA, "6.6.6.6"),
			endpoint.NewEndpoint("domain1.local", endpoint.RecordTypeA, "7.7.7.7"),
		},
	}
	err = uszipam.ApplyChanges(context.Background(), changes4)
	require.NoError(t, err)

	expectedServices4 := map[string][]*Service{
		"/skydns/local/domain2": {{Host: "site.local"}},
		"/skydns/local/domain1": {{Host: "5.5.5.5"}, {Host: "6.6.6.6"}, {Host: "7.7.7.7"}},
	}
	validateServices(client.services, expectedServices4, t, 4)
}

func applyServiceChanges(provider uszIpamProvider, changes *plan.Changes) error {
	ctx := context.Background()
	records, _ := provider.Records(ctx)
	for _, col := range [][]*endpoint.Endpoint{changes.Create, changes.UpdateNew, changes.Delete} {
		for _, record := range col {
			for _, existingRecord := range records {
				if existingRecord.DNSName == record.DNSName && existingRecord.RecordType == record.RecordType {
					mergeLabels(record, existingRecord.Labels)
				}
			}
		}
	}
	return provider.ApplyChanges(ctx, changes)
}

func validateServices(services map[string]Service, expectedServices map[string][]*Service, t *testing.T, step int) {
	t.Helper()
	for key, value := range services {
		keyParts := strings.Split(key, "/")
		expectedKey := strings.Join(keyParts[:len(keyParts)-value.TargetStrip], "/")
		expectedServiceEntries := expectedServices[expectedKey]
		if expectedServiceEntries == nil {
			t.Errorf("unexpected service %s", key)
			continue
		}
		found := false
		for i, expectedServiceEntry := range expectedServiceEntries {
			if value.Host == expectedServiceEntry.Host && value.Text == expectedServiceEntry.Text {
				expectedServiceEntries = append(expectedServiceEntries[:i], expectedServiceEntries[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected service %s: %s on step %d", key, value.Host, step)
		}
		if len(expectedServiceEntries) == 0 {
			delete(expectedServices, expectedKey)
		} else {
			expectedServices[expectedKey] = expectedServiceEntries
		}
	}
	if len(expectedServices) != 0 {
		t.Errorf("unmatched expected services: %+v on step %d", expectedServices, step)
	}
}

// mergeLabels adds keys to labels if not defined for the endpoint
func mergeLabels(e *endpoint.Endpoint, labels map[string]string) {
	for k, v := range labels {
		if e.Labels[k] == "" {
			e.Labels[k] = v
		}
	}
}
