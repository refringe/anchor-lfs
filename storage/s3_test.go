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
	objects      map[string][]byte
	uploads      map[string]map[int32][]byte
	nextUploadID int

	headErr error
	getErr  error
	putErr  error
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{objects: make(map[string][]byte), uploads: make(map[string]map[int32][]byte)}
}

// readSeekableBody reads body, rejecting unseekable bodies as the SDK does over plain HTTP.
func readSeekableBody(body io.Reader) ([]byte, error) {
	if _, ok := body.(io.Seeker); !ok {
		return nil, errors.New("unseekable stream is not supported without TLS and trailing checksum")
	}
	return io.ReadAll(body)
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
	data, err := readSeekableBody(input.Body)
	if err != nil {
		return nil, err
	}
	m.objects[aws.ToString(input.Key)] = data
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) CreateMultipartUpload(_ context.Context, _ *s3.CreateMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	m.nextUploadID++
	id := fmt.Sprintf("upload-%d", m.nextUploadID)
	m.uploads[id] = make(map[int32][]byte)
	return &s3.CreateMultipartUploadOutput{UploadId: aws.String(id)}, nil
}

func (m *mockS3Client) UploadPart(_ context.Context, input *s3.UploadPartInput, _ ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	parts, ok := m.uploads[aws.ToString(input.UploadId)]
	if !ok {
		return nil, &s3types.NoSuchUpload{Message: aws.String("no such upload")}
	}
	data, err := readSeekableBody(input.Body)
	if err != nil {
		return nil, err
	}
	number := aws.ToInt32(input.PartNumber)
	parts[number] = data
	return &s3.UploadPartOutput{ETag: aws.String(fmt.Sprintf("etag-%d", number))}, nil
}

func (m *mockS3Client) CompleteMultipartUpload(_ context.Context, input *s3.CompleteMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	id := aws.ToString(input.UploadId)
	parts, ok := m.uploads[id]
	if !ok {
		return nil, &s3types.NoSuchUpload{Message: aws.String("no such upload")}
	}
	var data []byte
	for _, part := range input.MultipartUpload.Parts {
		data = append(data, parts[aws.ToInt32(part.PartNumber)]...)
	}
	m.objects[aws.ToString(input.Key)] = data
	delete(m.uploads, id)
	return &s3.CompleteMultipartUploadOutput{}, nil
}

func (m *mockS3Client) AbortMultipartUpload(_ context.Context, input *s3.AbortMultipartUploadInput, _ ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	delete(m.uploads, aws.ToString(input.UploadId))
	return &s3.AbortMultipartUploadOutput{}, nil
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

// unseekable hides every method of r except Read.
func unseekable(r io.Reader) io.Reader {
	return struct{ io.Reader }{r}
}

func testS3Store(t *testing.T) (*S3, *mockS3Client) {
	t.Helper()
	client := newMockS3Client()
	return &S3{client: client, bucket: "test-bucket", prefix: "lfs/"}, client
}

func testPresignedS3Store(t *testing.T, presigner *mockPresigner) *PresignedS3 {
	t.Helper()
	store, _ := testS3Store(t)
	return &PresignedS3{S3: store, presigner: presigner}
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

// putSizes covers objects below, at, and above the multipart threshold.
var putSizes = []struct {
	name string
	size int64
}{
	{"single part", 11},
	{"exactly one part", s3PartSize},
	{"multipart", 2*s3PartSize + 123},
}

func TestS3PutAndGet(t *testing.T) {
	for _, tt := range putSizes {
		t.Run(tt.name, func(t *testing.T) {
			store, client := testS3Store(t)
			data := randomBytes(int(tt.size))
			oid := testutil.SHA256Hex(data)
			ctx := t.Context()

			if err := store.Put(ctx, "test", oid, unseekable(bytes.NewReader(data)), tt.size); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if len(client.uploads) != 0 {
				t.Errorf("%d multipart uploads left open", len(client.uploads))
			}

			reader, size, err := store.Get(ctx, "test", oid)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer func() { _ = reader.Close() }()

			if size != tt.size {
				t.Errorf("Get size = %d, want %d", size, tt.size)
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("data mismatch")
			}
		})
	}
}

func TestS3PutHashMismatch(t *testing.T) {
	for _, tt := range putSizes {
		t.Run(tt.name, func(t *testing.T) {
			store, client := testS3Store(t)
			data := randomBytes(int(tt.size))
			badOID := "0000000000000000000000000000000000000000000000000000000000000000"

			err := store.Put(t.Context(), "test", badOID, unseekable(bytes.NewReader(data)), tt.size)
			if !errors.Is(err, ErrHashMismatch) {
				t.Fatalf("Put error = %v, want ErrHashMismatch", err)
			}
			if len(client.objects) != 0 {
				t.Error("object with mismatched hash was written")
			}
			if len(client.uploads) != 0 {
				t.Errorf("%d multipart uploads left open", len(client.uploads))
			}
		})
	}
}

func TestS3PutShortBody(t *testing.T) {
	for _, tt := range putSizes {
		t.Run(tt.name, func(t *testing.T) {
			store, client := testS3Store(t)
			data := randomBytes(int(tt.size))
			oid := testutil.SHA256Hex(data)

			err := store.Put(t.Context(), "test", oid, unseekable(bytes.NewReader(data[:len(data)-1])), tt.size)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("Put error = %v, want io.ErrUnexpectedEOF", err)
			}
			if len(client.objects) != 0 {
				t.Error("object from a short body was written")
			}
			if len(client.uploads) != 0 {
				t.Errorf("%d multipart uploads left open", len(client.uploads))
			}
		})
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

	if err := store.Put(ctx, "test", oid, bytes.NewReader(data), int64(len(data))); err != nil {
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
		wantErr  error
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
			name:     "uppercase OID is normalised",
			prefix:   "lfs/",
			endpoint: "test",
			oid:      "4D7A214614AB2935C943F9E0FF69D22EADBB8F32B1258DAAA5E2CA24D17E2393",
			want:     "lfs/test/4d/7a/4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393",
		},
		{
			name:     "short OID rejected",
			prefix:   "lfs/",
			endpoint: "test",
			oid:      "abc",
			wantErr:  ErrInvalidOID,
		},
		{
			name:     "traversal rejected",
			prefix:   "lfs/",
			endpoint: "test",
			oid:      "../../../../../../../../../../../../../../../../../../../../etc/pw",
			wantErr:  ErrInvalidOID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &S3{bucket: "bucket", prefix: tt.prefix}
			got, err := store.objectKey(tt.endpoint, tt.oid)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("objectKey() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("objectKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestS3PresignGet(t *testing.T) {
	store := testPresignedS3Store(t, &mockPresigner{})

	href, err := store.PresignGet(t.Context(), "/org/repo", "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", 10*time.Minute)
	if err != nil {
		t.Fatalf("PresignGet: %v", err)
	}
	if href == "" {
		t.Error("expected non-empty presigned URL")
	}
}

func TestS3PresignPut(t *testing.T) {
	store := testPresignedS3Store(t, &mockPresigner{})

	href, err := store.PresignPut(t.Context(), "/org/repo", "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393", 10*time.Minute)
	if err != nil {
		t.Fatalf("PresignPut: %v", err)
	}
	if href == "" {
		t.Error("expected non-empty presigned URL")
	}
}

func TestNewS3PresignedURLs(t *testing.T) {
	for _, presigned := range []bool{false, true} {
		t.Run(fmt.Sprintf("presigned=%t", presigned), func(t *testing.T) {
			store, err := NewS3(t.Context(), S3Config{
				Bucket:          "test-bucket",
				Region:          "us-east-1",
				AccessKeyID:     "id",
				SecretAccessKey: "secret",
				PresignedURLs:   presigned,
			})
			if err != nil {
				t.Fatalf("NewS3: %v", err)
			}
			if _, ok := store.(PresignedURLProvider); ok != presigned {
				t.Errorf("adapter implements PresignedURLProvider = %t, want %t", ok, presigned)
			}
		})
	}
}

func TestS3PresignError(t *testing.T) {
	store := testPresignedS3Store(t, &mockPresigner{
		getErr: fmt.Errorf("presign failure"),
		putErr: fmt.Errorf("presign failure"),
	})

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
