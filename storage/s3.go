package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/refringe/anchor-lfs/internal/sanitise"
)

// Compile-time interface checks.
var (
	_ Adapter              = (*S3)(nil)
	_ PresignedURLProvider = (*S3)(nil)
)

// s3API is the subset of the S3 client used by the storage adapter, enabling test mocking.
type s3API interface {
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// s3Presigner is the subset of the S3 presign client used by the storage adapter.
type s3Presigner interface {
	PresignGetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
	PresignPutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

// S3Config holds the settings for creating an S3 storage adapter.
type S3Config struct {
	Bucket          string
	Region          string
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	Prefix          string
	PresignedURLs   bool
	ForcePathStyle  bool
}

// S3 stores objects in an S3-compatible bucket. It supports both AWS S3 and Cloudflare R2 through configurable
// endpoint and path style options.
type S3 struct {
	client        s3API
	presigner     s3Presigner
	bucket        string
	prefix        string
	presignedURLs bool
}

// NewS3 creates an S3 storage adapter with the given configuration.
func NewS3(ctx context.Context, cfg S3Config) (*S3, error) {
	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(cfg.Region))

	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	var s3Opts []func(*s3.Options)
	if cfg.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}
	if cfg.ForcePathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Opts...)
	presigner := s3.NewPresignClient(client)

	return &S3{
		client:        client,
		presigner:     presigner,
		bucket:        cfg.Bucket,
		prefix:        cfg.Prefix,
		presignedURLs: cfg.PresignedURLs,
	}, nil
}

// newS3WithClient creates an S3 adapter with injected dependencies for testing.
func newS3WithClient(client s3API, presigner s3Presigner, bucket, prefix string, presignedURLs bool) *S3 {
	return &S3{
		client:        client,
		presigner:     presigner,
		bucket:        bucket,
		prefix:        prefix,
		presignedURLs: presignedURLs,
	}
}

// Exists reports whether the object exists in the S3 bucket.
func (s *S3) Exists(ctx context.Context, endpoint, oid string) (bool, error) {
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(endpoint, oid)),
	})
	if err != nil {
		if isS3NotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("checking object %s: %w", oid, err)
	}
	return true, nil
}

// Get opens the object for reading and returns its size.
func (s *S3) Get(ctx context.Context, endpoint, oid string) (io.ReadCloser, int64, error) {
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(endpoint, oid)),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, 0, fmt.Errorf("opening object %s: %w", oid, fs.ErrNotExist)
		}
		return nil, 0, fmt.Errorf("opening object %s: %w", oid, err)
	}

	var size int64
	if resp.ContentLength != nil {
		size = *resp.ContentLength
	}
	return resp.Body, size, nil
}

// Put streams reader content to S3, verifying the SHA-256 hash matches the OID. If the hash does not match, the
// uploaded object is deleted and ErrHashMismatch is returned.
func (s *S3) Put(ctx context.Context, endpoint, oid string, reader io.Reader) error {
	hasher := sha256.New()
	tee := io.TeeReader(reader, hasher)

	key := s.objectKey(endpoint, oid)
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   tee,
	})
	if err != nil {
		return fmt.Errorf("writing object %s: %w", oid, err)
	}

	computed := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(computed, oid) {
		// Hash mismatch: clean up the uploaded object.
		_, _ = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(s.bucket),
			Key:    aws.String(key),
		})
		return fmt.Errorf("%w: expected %s, got %s", ErrHashMismatch, oid, computed)
	}

	return nil
}

// Size returns the size of the stored object in bytes.
func (s *S3) Size(ctx context.Context, endpoint, oid string) (int64, error) {
	resp, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(endpoint, oid)),
	})
	if err != nil {
		if isS3NotFound(err) {
			return 0, fmt.Errorf("stat object %s: %w", oid, fs.ErrNotExist)
		}
		return 0, fmt.Errorf("stat object %s: %w", oid, err)
	}

	if resp.ContentLength != nil {
		return *resp.ContentLength, nil
	}
	return 0, nil
}

// AvailableSpace returns math.MaxUint64 because S3 buckets have no practical storage limit.
func (s *S3) AvailableSpace(_ context.Context) (uint64, error) {
	return math.MaxUint64, nil
}

// PresignGet returns a presigned GET URL for direct client downloads.
func (s *S3) PresignGet(ctx context.Context, endpoint, oid string, expiry time.Duration) (string, error) {
	if !s.presignedURLs {
		return "", fmt.Errorf("presigned URLs are disabled")
	}

	resp, err := s.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(endpoint, oid)),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", fmt.Errorf("presigning GET for %s: %w", oid, err)
	}
	return resp.URL, nil
}

// PresignPut returns a presigned PUT URL for direct client uploads.
func (s *S3) PresignPut(ctx context.Context, endpoint, oid string, expiry time.Duration) (string, error) {
	if !s.presignedURLs {
		return "", fmt.Errorf("presigned URLs are disabled")
	}

	resp, err := s.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(endpoint, oid)),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", fmt.Errorf("presigning PUT for %s: %w", oid, err)
	}
	return resp.URL, nil
}

// objectKey returns the S3 object key for the given endpoint and OID, using the same two-level sharding as the local
// filesystem adapter.
func (s *S3) objectKey(endpoint, oid string) string {
	sanitised := sanitise.Endpoint(endpoint)
	if len(oid) < 4 {
		return s.prefix + sanitised + "/" + oid
	}
	return s.prefix + sanitised + "/" + oid[:2] + "/" + oid[2:4] + "/" + oid
}

// isS3NotFound reports whether the error indicates that the requested S3 object does not exist.
func isS3NotFound(err error) bool {
	if _, ok := errors.AsType[*s3types.NotFound](err); ok {
		return true
	}
	if _, ok := errors.AsType[*s3types.NoSuchKey](err); ok {
		return true
	}
	// The S3 HeadObject API returns a generic error with "NotFound" in the message for missing objects rather than a
	// typed error. Check for the HTTP 404 status code in the error message as a fallback.
	var respErr interface{ HTTPStatusCode() int }
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
		return true
	}
	return false
}
