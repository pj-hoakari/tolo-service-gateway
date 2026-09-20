package externaltoken_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pj-hoakari/tolo-service-gateway/internal/externaltoken"
)

const (
	testIntrospectionClientID = "gateway-introspection"
	testCredential            = "introspection-client-credential"
	testAccessToken           = "header.payload.signature"
)

type introspectionCall struct {
	authorization string
	contentType   string
	form          url.Values
}

type introspectionServer struct {
	mu       sync.Mutex
	status   int
	body     string
	delay    time.Duration
	requests int
	calls    []introspectionCall

	server *httptest.Server
}

func newIntrospectionServer(t *testing.T, body string) *introspectionServer {
	t.Helper()

	endpoint := &introspectionServer{
		mu:       sync.Mutex{},
		status:   http.StatusOK,
		body:     body,
		delay:    0,
		requests: 0,
		calls:    nil,
		server:   nil,
	}

	endpoint.server = httptest.NewServer(http.HandlerFunc(endpoint.serve))
	t.Cleanup(endpoint.server.Close)

	return endpoint
}

func (s *introspectionServer) serve(writer http.ResponseWriter, request *http.Request) {
	_ = request.ParseForm()

	s.mu.Lock()
	s.requests++
	s.calls = append(s.calls, introspectionCall{
		authorization: request.Header.Get("Authorization"),
		contentType:   request.Header.Get("Content-Type"),
		form:          request.PostForm,
	})
	body, status, delay := s.body, s.status, s.delay
	s.mu.Unlock()

	time.Sleep(delay)

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(body))
}

func (s *introspectionServer) answer(body string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.body, s.status = body, status
}

func (s *introspectionServer) setDelay(delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delay = delay
}

func (s *introspectionServer) asked() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.requests
}

func (s *introspectionServer) lastCall(t *testing.T) introspectionCall {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.calls) == 0 {
		t.Fatal("the introspection endpoint was not asked, want one request")
	}

	return s.calls[len(s.calls)-1]
}

func newIntrospector(t *testing.T, endpoint *introspectionServer, config externaltoken.IntrospectorConfig) *externaltoken.Introspector {
	t.Helper()

	config.Endpoint = endpoint.server.URL

	if config.ClientID == "" {
		config.ClientID = testIntrospectionClientID
	}

	if config.ClientSecret == "" {
		config.ClientSecret = testCredential
	}

	if config.HTTPClient == nil {
		config.HTTPClient = endpoint.server.Client()
	}

	introspector, err := externaltoken.NewIntrospector(config)
	if err != nil {
		t.Fatalf("NewIntrospector() error = %v, want nil", err)
	}

	return introspector
}

func activeDocument(jti string) string {
	return `{"active":true,"jti":"` + jti + `","sub":"user-1","client_id":"admin-ui","token_use":"tenant_access"}`
}

func mustAsk(t *testing.T, introspector *externaltoken.Introspector, jti string, expiresAt time.Time) bool {
	t.Helper()

	active, err := introspector.Active(t.Context(), testAccessToken, jti, expiresAt)
	if err != nil {
		t.Fatalf("Active() error = %v, want nil", err)
	}

	return active
}

func TestNewIntrospectorRejectsAnIncompleteConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]externaltoken.IntrospectorConfig{
		"without an endpoint":         {ClientID: testIntrospectionClientID, ClientSecret: testCredential},
		"with a relative endpoint":    {Endpoint: "/introspect", ClientID: testIntrospectionClientID, ClientSecret: testCredential},
		"without a client ID":         {Endpoint: "https://idp.example.com/introspect", ClientSecret: testCredential},
		"without the client's secret": {Endpoint: "https://idp.example.com/introspect", ClientID: testIntrospectionClientID},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := externaltoken.NewIntrospector(config); !errors.Is(err, externaltoken.ErrInvalidIntrospection) {
				t.Errorf("NewIntrospector() error = %v, want %v", err, externaltoken.ErrInvalidIntrospection)
			}
		})
	}
}

func TestIntrospectorReportsWhetherTheTokenIsActive(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body string
		want bool
	}{
		"an active token":  {body: activeDocument(testJTI), want: true},
		"a revoked token":  {body: `{"active":false}`, want: false},
		"an unknown token": {body: `{"active": false, "scope": ""}`, want: false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			endpoint := newIntrospectionServer(t, test.body)
			introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{})

			if got := mustAsk(t, introspector, testJTI, time.Time{}); got != test.want {
				t.Errorf("Active() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestIntrospectorAsksTheEndpointTheWayTheSpecificationRequires(t *testing.T) {
	t.Parallel()

	endpoint := newIntrospectionServer(t, activeDocument(testJTI))
	introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{})

	mustAsk(t, introspector, testJTI, time.Time{})

	call := endpoint.lastCall(t)

	if got, want := call.contentType, "application/x-www-form-urlencoded"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	if got, want := call.form.Get("token"), testAccessToken; got != want {
		t.Errorf("form token = %q, want the access token", got)
	}

	if got, want := call.form.Get("token_type_hint"), "access_token"; got != want {
		t.Errorf("form token_type_hint = %q, want %q", got, want)
	}
}

func TestIntrospectorFormEncodesTheClientCredentialsForBasic(t *testing.T) {
	t.Parallel()

	const (
		clientID   = "gateway client/+ id"
		credential = "introspection client/+ credential"
	)

	endpoint := newIntrospectionServer(t, activeDocument(testJTI))
	introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{
		ClientID:     clientID,
		ClientSecret: credential,
	})

	mustAsk(t, introspector, testJTI, time.Time{})

	request := &http.Request{Header: http.Header{"Authorization": {endpoint.lastCall(t).authorization}}}

	gotID, gotSecret, carried := request.BasicAuth()
	if !carried {
		t.Fatalf("Authorization = %q, want basic credentials", endpoint.lastCall(t).authorization)
	}

	if want := url.QueryEscape(clientID); gotID != want {
		t.Errorf("basic user = %q, want %q", gotID, want)
	}

	if want := url.QueryEscape(credential); gotSecret != want {
		t.Errorf("basic password = %q, want the form-encoded secret", gotSecret)
	}
}

func TestIntrospectorAnswersFromItsCacheWithinTheTTL(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"an active token": activeDocument(testJTI),
		"a revoked token": `{"active":false}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			endpoint := newIntrospectionServer(t, body)
			clock := newTestClock()
			introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{Clock: clock.Now})

			first := mustAsk(t, introspector, testJTI, time.Time{})

			clock.advance(externaltoken.DefaultIntrospectionCacheTTL - time.Second)

			if got := mustAsk(t, introspector, testJTI, time.Time{}); got != first {
				t.Errorf("Active() = %t on the cached answer, want %t", got, first)
			}

			if got := endpoint.asked(); got != 1 {
				t.Errorf("introspection requests = %d, want 1", got)
			}

			clock.advance(2 * time.Second)

			mustAsk(t, introspector, testJTI, time.Time{})

			if got := endpoint.asked(); got != 2 {
				t.Errorf("introspection requests = %d after the TTL, want 2", got)
			}
		})
	}
}

func TestIntrospectorKeepsTheAnswerNoLongerThanTheToken(t *testing.T) {
	t.Parallel()

	endpoint := newIntrospectionServer(t, activeDocument(testJTI))
	clock := newTestClock()
	introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{Clock: clock.Now})

	expiresAt := clock.Now().Add(10 * time.Second)

	mustAsk(t, introspector, testJTI, expiresAt)

	clock.advance(11 * time.Second)

	mustAsk(t, introspector, testJTI, expiresAt)

	if got := endpoint.asked(); got != 2 {
		t.Errorf("introspection requests = %d, want 2 once the token itself expired", got)
	}
}

func TestIntrospectorKeepsAskingAfterAFailure(t *testing.T) {
	t.Parallel()

	endpoint := newIntrospectionServer(t, "")
	endpoint.answer("", http.StatusServiceUnavailable)

	introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{})

	if _, err := introspector.Active(t.Context(), testAccessToken, testJTI, time.Time{}); err == nil {
		t.Fatal("Active() error = nil, want the failure reported")
	}

	endpoint.answer(activeDocument(testJTI), http.StatusOK)

	if !mustAsk(t, introspector, testJTI, time.Time{}) {
		t.Error("Active() = false, want the token reported active once the endpoint answers")
	}

	if got := endpoint.asked(); got != 2 {
		t.Errorf("introspection requests = %d, want 2 because failures are not cached", got)
	}
}

func TestIntrospectorAsksOnceForConcurrentCallers(t *testing.T) {
	t.Parallel()

	const callers = 8

	endpoint := newIntrospectionServer(t, activeDocument(testJTI))
	endpoint.setDelay(20 * time.Millisecond)

	introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{})

	var group sync.WaitGroup

	for range callers {
		group.Add(1)

		go func() {
			defer group.Done()

			if _, err := introspector.Active(t.Context(), testAccessToken, testJTI, time.Time{}); err != nil {
				t.Errorf("Active() error = %v, want nil", err)
			}
		}()
	}

	group.Wait()

	if got := endpoint.asked(); got != 1 {
		t.Errorf("introspection requests = %d, want 1 for %d concurrent callers", got, callers)
	}
}

func TestIntrospectorKeepsItsCacheUnderTheLimit(t *testing.T) {
	t.Parallel()

	endpoint := newIntrospectionServer(t, `{"active":true}`)
	clock := newTestClock()
	introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{Clock: clock.Now, MaxEntries: 2})

	for _, jti := range []string{"jti-1", "jti-2", "jti-3"} {
		mustAsk(t, introspector, jti, time.Time{})
		clock.advance(time.Second)
	}

	mustAsk(t, introspector, "jti-1", time.Time{})

	if got := endpoint.asked(); got != 4 {
		t.Errorf("introspection requests = %d, want 4 because the oldest answer was dropped", got)
	}

	mustAsk(t, introspector, "jti-3", time.Time{})

	if got := endpoint.asked(); got != 4 {
		t.Errorf("introspection requests = %d, want the newest answers kept", got)
	}
}

func TestIntrospectorRejectsAnAnswerItCannotUse(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body   string
		status int
	}{
		"a server failure":                       {body: "", status: http.StatusServiceUnavailable},
		"an unauthenticated client":              {body: "", status: http.StatusUnauthorized},
		"a body that is not JSON":                {body: "not json", status: http.StatusOK},
		"a body without active":                  {body: `{"sub":"user-1"}`, status: http.StatusOK},
		"an active member that is not a boolean": {body: `{"active":"true"}`, status: http.StatusOK},
		"an answer for another token":            {body: activeDocument("another-jti"), status: http.StatusOK},
		"a body over the size limit":             {body: `{"active":true,"scope":"` + strings.Repeat("a", 1<<20) + `"}`, status: http.StatusOK},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			endpoint := newIntrospectionServer(t, test.body)
			endpoint.answer(test.body, test.status)

			introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{})

			active, err := introspector.Active(t.Context(), testAccessToken, testJTI, time.Time{})
			if !errors.Is(err, externaltoken.ErrIntrospectionUnavailable) {
				t.Fatalf("Active() error = %v, want %v", err, externaltoken.ErrIntrospectionUnavailable)
			}

			if active {
				t.Error("Active() = true, want false when the answer cannot be used")
			}
		})
	}
}

func TestIntrospectorReportsAnEndpointThatDoesNotAnswerInTime(t *testing.T) {
	t.Parallel()

	endpoint := newIntrospectionServer(t, activeDocument(testJTI))
	endpoint.setDelay(200 * time.Millisecond)

	introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{Timeout: 10 * time.Millisecond})

	if _, err := introspector.Active(t.Context(), testAccessToken, testJTI, time.Time{}); !errors.Is(err, externaltoken.ErrIntrospectionUnavailable) {
		t.Errorf("Active() error = %v, want %v", err, externaltoken.ErrIntrospectionUnavailable)
	}
}

func TestIntrospectorRefusesToAskWithoutAJTI(t *testing.T) {
	t.Parallel()

	endpoint := newIntrospectionServer(t, activeDocument(testJTI))
	introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{})

	if _, err := introspector.Active(t.Context(), testAccessToken, "", time.Time{}); !errors.Is(err, externaltoken.ErrIntrospectionUnavailable) {
		t.Errorf("Active() error = %v, want %v", err, externaltoken.ErrIntrospectionUnavailable)
	}

	if got := endpoint.asked(); got != 0 {
		t.Errorf("introspection requests = %d, want none", got)
	}
}

func TestIntrospectorKeepsTheTokenAndTheSecretOutOfItsErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body   string
		status int
	}{
		"a server failure":            {body: testAccessToken, status: http.StatusServiceUnavailable},
		"a body that is not JSON":     {body: testAccessToken, status: http.StatusOK},
		"an answer for another token": {body: activeDocument("another-jti"), status: http.StatusOK},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			endpoint := newIntrospectionServer(t, test.body)
			endpoint.answer(test.body, test.status)

			introspector := newIntrospector(t, endpoint, externaltoken.IntrospectorConfig{})

			_, err := introspector.Active(t.Context(), testAccessToken, testJTI, time.Time{})
			if err == nil {
				t.Fatal("Active() error = nil, want the failure reported")
			}

			for what, secret := range map[string]string{"the token": testAccessToken, "the client secret": testCredential} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("Active() error = %q, want it to leave %s out", err, what)
				}
			}
		})
	}
}
