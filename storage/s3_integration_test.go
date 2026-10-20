package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/refringe/anchor-lfs/internal/testutil"
)

// integrationS3Store returns a presigning S3 adapter backed by a fresh bucket on ANCHOR_LFS_TEST_S3_ENDPOINT.
func integrationS3Store(t *testing.T) *PresignedS3 {
	t.Helper()
	endpoint := os.Getenv("ANCHOR_LFS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("ANCHOR_LFS_TEST_S3_ENDPOINT is not set")
	}

	ctx := t.Context()
	bucket := fmt.Sprintf("anchor-lfs-test-%d", time.Now().UnixNano())
	client, err := newS3Client(ctx, S3Config{
		Region:          "us-east-1",
		Endpoint:        endpoint,
		AccessKeyID:     os.Getenv("ANCHOR_LFS_TEST_S3_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("ANCHOR_LFS_TEST_S3_SECRET_ACCESS_KEY"),
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatalf("newS3Client: %v", err)
	}
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	t.Cleanup(func() { deleteBucket(t, client, bucket) })
	return &PresignedS3{S3: &S3{client: client, bucket: bucket}, presigner: s3.NewPresignClient(client)}
}

// deleteBucket removes every object in bucket and then the bucket itself.
func deleteBucket(t *testing.T, client *s3.Client, bucket string) {
	t.Helper()
	ctx := context.Background()
	pages := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			t.Errorf("listing objects in %s: %v", bucket, err)
			return
		}
		for _, obj := range page.Contents {
			if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: obj.Key}); err != nil {
				t.Errorf("deleting %s: %v", aws.ToString(obj.Key), err)
			}
		}
	}
	if _, err := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Errorf("deleting bucket %s: %v", bucket, err)
	}
}

// randomBytes returns n deterministic pseudo-random bytes.
func randomBytes(n int) []byte {
	data := make([]byte, n)
	_, _ = rand.NewChaCha8([32]byte{}).Read(data)
	return data
}

func TestS3IntegrationPutAndGet(t *testing.T) {
	for _, tt := range putSizes {
		t.Run(tt.name, func(t *testing.T) {
			store := integrationS3Store(t)
			ctx := t.Context()
			data := randomBytes(int(tt.size))
			oid := testutil.SHA256Hex(data)

			if err := store.Put(ctx, "/org/repo", oid, unseekable(bytes.NewReader(data)), tt.size); err != nil {
				t.Fatalf("Put: %v", err)
			}

			reader, size, err := store.Get(ctx, "/org/repo", oid)
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
				t.Fatal("downloaded data does not match uploaded data")
			}
		})
	}
}

func TestS3IntegrationPutHashMismatch(t *testing.T) {
	for _, tt := range putSizes {
		t.Run(tt.name, func(t *testing.T) {
			store := integrationS3Store(t)
			ctx := t.Context()
			data := randomBytes(int(tt.size))
			badOID := "0000000000000000000000000000000000000000000000000000000000000000"

			err := store.Put(ctx, "/org/repo", badOID, unseekable(bytes.NewReader(data)), tt.size)
			if !errors.Is(err, ErrHashMismatch) {
				t.Fatalf("Put error = %v, want ErrHashMismatch", err)
			}

			exists, err := store.Exists(ctx, "/org/repo", badOID)
			if err != nil {
				t.Fatalf("Exists: %v", err)
			}
			if exists {
				t.Fatal("object with mismatched hash was left in the bucket")
			}
		})
	}
}

func TestS3IntegrationPresignedURLs(t *testing.T) {
	data := randomBytes(1 << 20)
	corrupted := slices.Clone(data)
	corrupted[0] ^= 0xff

	tests := []struct {
		name       string
		body       []byte
		dropHeader bool
		wantStored bool
	}{
		{name: "matching body", body: data, wantStored: true},
		{name: "corrupted body", body: corrupted},
		{name: "longer body", body: append(slices.Clone(data), 0)},
		{name: "missing checksum header", body: data, dropHeader: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := integrationS3Store(t)
			ctx := t.Context()
			oid := testutil.SHA256Hex(data)

			href, header, err := store.PresignPut(ctx, "/org/repo", oid, int64(len(data)), time.Minute)
			if err != nil {
				t.Fatalf("PresignPut: %v", err)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPut, href, bytes.NewReader(tt.body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if !tt.dropHeader {
				for name, value := range header {
					req.Header.Set(name, value)
				}
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("PUT: %v", err)
			}
			_ = resp.Body.Close()
			if accepted := resp.StatusCode == http.StatusOK; accepted != tt.wantStored {
				t.Errorf("PUT status = %d, want accepted = %t", resp.StatusCode, tt.wantStored)
			}

			exists, err := store.Exists(ctx, "/org/repo", oid)
			if err != nil {
				t.Fatalf("Exists: %v", err)
			}
			if exists != tt.wantStored {
				t.Errorf("object stored = %t, want %t", exists, tt.wantStored)
			}
			if tt.wantStored {
				assertPresignedGet(t, store, oid, data)
			}
		})
	}
}

// assertPresignedGet downloads oid through a presigned URL without extra headers and compares it with want.
func assertPresignedGet(t *testing.T, store *PresignedS3, oid string, want []byte) {
	t.Helper()
	href, err := store.PresignGet(t.Context(), "/org/repo", oid, time.Minute)
	if err != nil {
		t.Fatalf("PresignGet: %v", err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, href, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading GET body: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("presigned download does not match uploaded data")
	}
}
