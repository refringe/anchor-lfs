package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/refringe/anchor-lfs/internal/testutil"
)

// mockS3Client implements s3API for testing.
type mockS3Client struct {
	objects map[string][]byte

	headErr   error
	getErr    error
	putErr    error
	deleteErr error
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{objects: make(map[string][]byte)}
}

func (m *mockS3Client) HeadObject(_ context.Context, input *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if m.headErr != nil {
		return nil, m.headErr
	}
	key := aws.ToString(input.Key)
	data, ok := m.objects[key]
	if !ok {
		return nil, &s3types.NotFound{Message: aws.String("not found")}
	}
	size := int64(len(data))
	return &s3.HeadObjectOutput{ContentLength: &size}, nil
}

func (m *mockS3Client) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	key := aws.ToString(input.Key)
	data, ok := m.objects[key]
	if !ok {
		return nil, &s3types.NoSuchKey{Message: aws.String("no such key")}
	}
	size := int64(len(data))
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: &size,
	}, nil
}

func (m *mockS3Client) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	key := aws.ToString(input.Key)
	data, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	m.objects[key] = data
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}
	key := aws.ToString(input.Key)
	delete(m.objects, key)
	return &s3.DeleteObjectOutput{}, nil
}

// mockPresigner implements s3Presigner for testing.
type mockPresigner struct {
	getErr error
	putErr error
}

func (m *mockPresigner) PresignGetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return &v4.PresignedHTTPRequest{
		URL: fmt.Sprintf("https://s3.example.com/%s/%s?presigned=get", aws.ToString(input.Bucket), aws.ToString(input.Key)),
	}, nil
}

func (m *mockPresigner) PresignPutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	return &v4.PresignedHTTPRequest{
		URL: fmt.Sprintf("https://s3.example.com/%s/%s?presigned=put", aws.ToString(input.Bucket), aws.ToString(input.Key)),
	}, nil
}

func testS3Store(t *testing.T) (*S3, *mockS3Client) {
	t.Helper()
	client := newMockS3Client()
	presigner := &mockPresigner{}
	store := newS3WithClient(client, presigner, "test-bucket", "lfs/", true)
	return store, client
}

func TestS3Exists(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mockS3Client)
		want    bool
		wantErr bool
	}{
		{
			name: "object exists",
			setup: func(m *mockS3Client) {
				m.objects["lfs/test/ab/cd/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"] = []byte("data")
			},
			want: true,
		},
		{
			name:  "object not found",
			setup: func(_ *mockS3Client) {},
			want:  false,
		},
		{
			name: "API error",
			setup: func(m *mockS3Client) {
				m.headErr = fmt.Errorf("network failure")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, client := testS3Store(t)
			tt.setup(client)

			got, err := store.Exists(t.Context(), "test", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
			if (err != nil) != tt.wantErr {
				t.Fatalf("Exists() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Exists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestS3PutAndGet(t *testing.T) {
	store, _ := testS3Store(t)
	data := []byte("hello world")
	oid := testutil.SHA256Hex(data)
	ctx := t.Context()

	if err := store.Put(ctx, "test", oid, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	exists, err := store.Exists(ctx, "test", oid)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected object to exist")
	}

	reader, size, err := store.Get(ctx, "test", oid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = reader.Close() }()

	if size != int64(len(data)) {
		t.Errorf("Get size = %d, want %d", size, len(data))
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("data mismatch")
	}
}

func TestS3PutHashMismatch(t *testing.T) {
	store, client := testS3Store(t)
	data := []byte("hello world")
	badOID := "0000000000000000000000000000000000000000000000000000000000000000"
	ctx := t.Context()

	err := store.Put(ctx, "test", badOID, bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
	if !errors.Is(err, ErrHashMismatch) {
		t.Errorf("expected ErrHashMismatch, got %v", err)
	}

	// Verify the object was deleted after hash mismatch.
	key := store.objectKey("test", badOID)
	if _, ok := client.objects[key]; ok {
		t.Error("object should have been deleted after hash mismatch")
	}
}

func TestS3GetNotFound(t *testing.T) {
	store, _ := testS3Store(t)
	_, _, err := store.Get(t.Context(), "test", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err == nil {
		t.Fatal("expected error for missing object")
	}
}

func TestS3Size(t *testing.T) {
	store, _ := testS3Store(t)
	data := []byte("hello world")
	oid := testutil.SHA256Hex(data)
	ctx := t.Context()

	if err := store.Put(ctx, "test", oid, bytes.NewReader(data)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	size, err := store.Size(ctx, "test", oid)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != int64(len(data)) {
		t.Errorf("Size = %d, want %d", size, len(data))
	}
}

func TestS3SizeNotFound(t *testing.T) {
	store, _ := testS3Store(t)
	_, err := store.Size(t.Context(), "test", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err == nil {
		t.Fatal("expected error for missing object")
	}
}

func TestS3AvailableSpace(t *testing.T) {
	store, _ := testS3Store(t)
	space, err := store.AvailableSpace(t.Context())
	if err != nil {
		t.Fatalf("AvailableSpace: %v", err)
	}
	if space != math.MaxUint64 {
		t.Errorf("AvailableSpace = %d, want math.MaxUint64", space)
	}
}

func TestS3ObjectKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		endpoint string
		oid      string
		want     string
	}{
		{
			name:     "standard OID with prefix",
			prefix:   "lfs/",
			endpoint: "/org/repo",
			oid:      "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393",
			want:     "lfs/org_repo/4d/7a/4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393",
		},
		{
			name:     "empty prefix",
			prefix:   "",
			endpoint: "/org/repo",
			oid:      "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393",
			want:     "org_repo/4d/7a/4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393",
		},
		{
			name:     "short OID fallback",
			prefix:   "lfs/",
			endpoint: "test",
			oid:      "abc",
			want:     "lfs/test/abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newS3WithClient(nil, nil, "bucket", tt.prefix, false)
			got := store.objectKey(tt.endpoint, tt.oid)
			if got != tt.want {
				t.Errorf("objectKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestS3PresignGet(t *testing.T) {
	client := newMockS3Client()
	presigner := &mockPresigner{}
	store := newS3WithClient(client, presigner, "test-bucket", "lfs/", true)

	href, err := store.PresignGet(t.Context(), "/org/repo", "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", 10*time.Minute)
	if err != nil {
		t.Fatalf("PresignGet: %v", err)
	}
	if href == "" {
		t.Error("expected non-empty presigned URL")
	}
}

func TestS3PresignPut(t *testing.T) {
	client := newMockS3Client()
	presigner := &mockPresigner{}
	store := newS3WithClient(client, presigner, "test-bucket", "lfs/", true)

	href, err := store.PresignPut(t.Context(), "/org/repo", "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", 10*time.Minute)
	if err != nil {
		t.Fatalf("PresignPut: %v", err)
	}
	if href == "" {
		t.Error("expected non-empty presigned URL")
	}
}

func TestS3PresignDisabled(t *testing.T) {
	client := newMockS3Client()
	presigner := &mockPresigner{}
	store := newS3WithClient(client, presigner, "test-bucket", "lfs/", false)

	_, err := store.PresignGet(t.Context(), "/org/repo", "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", 10*time.Minute)
	if err == nil {
		t.Fatal("expected error when presigned URLs are disabled")
	}

	_, err = store.PresignPut(t.Context(), "/org/repo", "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", 10*time.Minute)
	if err == nil {
		t.Fatal("expected error when presigned URLs are disabled")
	}
}

func TestS3PresignError(t *testing.T) {
	client := newMockS3Client()
	presigner := &mockPresigner{
		getErr: fmt.Errorf("presign failure"),
		putErr: fmt.Errorf("presign failure"),
	}
	store := newS3WithClient(client, presigner, "test-bucket", "lfs/", true)

	_, err := store.PresignGet(t.Context(), "/org/repo", "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", 10*time.Minute)
	if err == nil {
		t.Fatal("expected error from presigner")
	}

	_, err = store.PresignPut(t.Context(), "/org/repo", "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", 10*time.Minute)
	if err == nil {
		t.Fatal("expected error from presigner")
	}
}

func TestIsS3NotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "NotFound type",
			err:  &s3types.NotFound{Message: aws.String("not found")},
			want: true,
		},
		{
			name: "NoSuchKey type",
			err:  &s3types.NoSuchKey{Message: aws.String("no such key")},
			want: true,
		},
		{
			name: "generic error",
			err:  fmt.Errorf("network error"),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isS3NotFound(tt.err); got != tt.want {
				t.Errorf("isS3NotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}
