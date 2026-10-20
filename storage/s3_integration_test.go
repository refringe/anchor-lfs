package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/refringe/anchor-lfs/internal/testutil"
)

// integrationS3Store returns an S3 adapter backed by a fresh bucket on the server named by ANCHOR_LFS_TEST_S3_ENDPOINT.
func integrationS3Store(t *testing.T) *S3 {
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
	return &S3{client: client, bucket: bucket}
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
