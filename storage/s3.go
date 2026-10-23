package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/refringe/anchor-lfs/internal/sanitise"
)

// s3PartSize is the default part size for uploads, and s3MaxParts is S3's limit on parts per multipart upload.
const (
	s3PartSize int64 = 8 << 20
	s3MaxParts int64 = 10000
)

// s3MaxPutSize is the largest object S3 accepts in a single PUT request.
const s3MaxPutSize int64 = 5 << 30

// s3MaxIdleConns is the number of idle connections to the S3 endpoint kept open for reuse.
const s3MaxIdleConns = 64

// ErrObjectTooLarge is returned when an object is larger than S3 accepts for the kind of upload requested.
var ErrObjectTooLarge = errors.New("object too large for this kind of S3 upload")

// Compile-time interface checks.
var (
	_ Adapter              = (*S3)(nil)
	_ Adapter              = (*PresignedS3)(nil)
	_ PresignedURLProvider = (*PresignedS3)(nil)
)

// s3API is the subset of the S3 client used by the storage adapter, enabling test mocking.
type s3API interface {
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
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

// S3 stores objects in an S3-compatible bucket, such as AWS S3 or Cloudflare R2, with transfers proxied by the server.
type S3 struct {
	client s3API
	bucket string
	prefix string
}

// PresignedS3 is an S3 adapter that hands clients presigned URLs for direct transfers to and from the bucket.
type PresignedS3 struct {
	*S3
	presigner s3Presigner
}

// NewS3 creates an S3 storage adapter, returning a *PresignedS3 when cfg.PresignedURLs is set and an *S3 otherwise.
func NewS3(ctx context.Context, cfg S3Config) (Adapter, error) {
	client, err := newS3Client(ctx, cfg)
	if err != nil {
		return nil, err
	}
	store := &S3{client: client, bucket: cfg.Bucket, prefix: cfg.Prefix}
	if cfg.PresignedURLs {
		return &PresignedS3{S3: store, presigner: s3.NewPresignClient(client)}, nil
	}
	return store, nil
}

// newS3Client builds an S3 client from the region, credentials, endpoint and path style in cfg.
func newS3Client(ctx context.Context, cfg S3Config) (*s3.Client, error) {
	httpClient := awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) {
		t.MaxIdleConnsPerHost = s3MaxIdleConns
	})
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithHTTPClient(httpClient),
	}

	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.ForcePathStyle
		o.DisableLogOutputChecksumValidationSkipped = true
	}), nil
}

// Exists reports whether the object exists in the S3 bucket.
func (s *S3) Exists(ctx context.Context, endpoint, oid string) (bool, error) {
	key, err := s.objectKey(endpoint, oid)
	if err != nil {
		return false, err
	}
	_, err = s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
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
	key, err := s.objectKey(endpoint, oid)
	if err != nil {
		return nil, 0, err
	}
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
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

// Put uploads size bytes from reader, or all of it if size is negative, storing the object only if the SHA-256 matches.
func (s *S3) Put(ctx context.Context, endpoint, oid string, reader io.Reader, size int64) error {
	key, err := s.objectKey(endpoint, oid)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	body := io.TeeReader(reader, hasher)
	if size < 0 {
		return s.putUnknownSize(ctx, key, oid, body, hasher)
	}
	partSize := max(s3PartSize, (size+s3MaxParts-1)/s3MaxParts)

	if size > partSize {
		return s.putMultipart(ctx, key, oid, body, hasher, size, partSize)
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(body, buf); err != nil {
		return fmt.Errorf("reading object %s: %w", oid, err)
	}
	return s.putObject(ctx, key, oid, buf, hasher)
}

// putUnknownSize uploads body until it ends, in one PUT if it fits in a part and as a multipart upload otherwise.
func (s *S3) putUnknownSize(ctx context.Context, key, oid string, body io.Reader, hasher hash.Hash) error {
	first := make([]byte, s3PartSize)
	n, err := fill(body, first)
	if errors.Is(err, io.EOF) {
		return s.putObject(ctx, key, oid, first[:n], hasher)
	}
	if err != nil {
		return fmt.Errorf("reading object %s: %w", oid, err)
	}
	return s.putMultipart(ctx, key, oid, io.MultiReader(bytes.NewReader(first), body), hasher, -1, s3PartSize)
}

// putObject writes data in a single PUT if the SHA-256 of everything hashed so far matches the OID.
func (s *S3) putObject(ctx context.Context, key, oid string, data []byte, hasher hash.Hash) error {
	if err := verifyOID(hasher, oid); err != nil {
		return err
	}
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
	})
	if err != nil {
		return fmt.Errorf("writing object %s: %w", oid, err)
	}
	return nil
}

// fill reads from r until buf is full or r ends, returning io.EOF only when r ended first.
func fill(r io.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		read, err := r.Read(buf[n:])
		n += read
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// putMultipart uploads size bytes of body, or all of it when size is negative, completing only if the SHA-256 matches.
func (s *S3) putMultipart(ctx context.Context, key, oid string, body io.Reader, hasher hash.Hash, size, partSize int64) (err error) {
	created, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:            aws.String(s.bucket),
		Key:               aws.String(key),
		ChecksumAlgorithm: s3types.ChecksumAlgorithmCrc32,
	})
	if err != nil {
		return fmt.Errorf("starting multipart upload for %s: %w", oid, err)
	}
	defer func() {
		if err != nil {
			_, _ = s.client.AbortMultipartUpload(context.WithoutCancel(ctx), &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(s.bucket),
				Key:      aws.String(key),
				UploadId: created.UploadId,
			})
		}
	}()

	buf := make([]byte, partSize)
	var parts []s3types.CompletedPart
	for number := int32(1); size != 0; number++ {
		var n int
		if size > 0 {
			n, err = io.ReadFull(body, buf[:min(partSize, size)])
		} else {
			n, err = fill(body, buf)
			if errors.Is(err, io.EOF) {
				size, err = 0, nil
			}
		}
		if err != nil {
			return fmt.Errorf("reading object %s: %w", oid, err)
		}
		if n == 0 {
			break
		}
		if int64(number) > s3MaxParts {
			return fmt.Errorf("%w: %s has more than %d parts of %d bytes", ErrObjectTooLarge, oid, s3MaxParts, partSize)
		}
		out, err := s.client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:            aws.String(s.bucket),
			Key:               aws.String(key),
			UploadId:          created.UploadId,
			PartNumber:        aws.Int32(number),
			Body:              bytes.NewReader(buf[:n]),
			ContentLength:     aws.Int64(int64(n)),
			ChecksumAlgorithm: s3types.ChecksumAlgorithmCrc32,
		})
		if err != nil {
			return fmt.Errorf("uploading part %d of %s: %w", number, oid, err)
		}
		parts = append(parts, s3types.CompletedPart{
			ETag:          out.ETag,
			PartNumber:    aws.Int32(number),
			ChecksumCRC32: out.ChecksumCRC32,
		})
		if size > 0 {
			size -= int64(n)
		}
	}

	if err := verifyOID(hasher, oid); err != nil {
		return err
	}
	_, err = s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(s.bucket),
		Key:             aws.String(key),
		UploadId:        created.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		return fmt.Errorf("completing multipart upload for %s: %w", oid, err)
	}
	return nil
}

// verifyOID returns ErrHashMismatch unless the hash computed so far equals the OID.
func verifyOID(hasher hash.Hash, oid string) error {
	computed := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(computed, oid) {
		return fmt.Errorf("%w: expected %s, got %s", ErrHashMismatch, oid, computed)
	}
	return nil
}

// Size returns the size of the stored object in bytes.
func (s *S3) Size(ctx context.Context, endpoint, oid string) (int64, error) {
	key, err := s.objectKey(endpoint, oid)
	if err != nil {
		return 0, err
	}
	resp, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
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

// Check confirms the bucket exists and the configured credentials and region can reach it.
func (s *S3) Check(ctx context.Context) error {
	if _, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)}); err != nil {
		return fmt.Errorf("checking S3 bucket %q: %w", s.bucket, err)
	}
	return nil
}

// AvailableSpace returns math.MaxUint64 because S3 buckets have no practical storage limit.
func (s *S3) AvailableSpace(_ context.Context) (uint64, error) {
	return math.MaxUint64, nil
}

// PresignGet returns a presigned GET URL for direct client downloads.
func (s *PresignedS3) PresignGet(ctx context.Context, endpoint, oid string, expiry time.Duration) (string, error) {
	key, err := s.objectKey(endpoint, oid)
	if err != nil {
		return "", err
	}

	resp, err := s.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", fmt.Errorf("presigning GET for %s: %w", oid, err)
	}
	return resp.URL, nil
}

// PresignPut returns a PUT URL accepting only size bytes that hash to oid, and the headers the upload must send.
func (s *PresignedS3) PresignPut(ctx context.Context, endpoint, oid string, size int64, expiry time.Duration) (string, map[string]string, error) {
	key, err := s.objectKey(endpoint, oid)
	if err != nil {
		return "", nil, err
	}
	if size > s3MaxPutSize {
		return "", nil, fmt.Errorf("%w: %d bytes exceeds %d", ErrObjectTooLarge, size, s3MaxPutSize)
	}
	digest, err := hex.DecodeString(oid)
	if err != nil {
		return "", nil, fmt.Errorf("decoding OID %s: %w", oid, err)
	}

	resp, err := s.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:         aws.String(s.bucket),
		Key:            aws.String(key),
		ContentLength:  aws.Int64(size),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest)),
	}, s3.WithPresignExpires(expiry), withSignedHeaders)
	if err != nil {
		return "", nil, fmt.Errorf("presigning PUT for %s: %w", oid, err)
	}

	header := make(map[string]string)
	for name, values := range resp.SignedHeader {
		if name != "Host" && name != "Content-Length" && len(values) > 0 {
			header[name] = values[0]
		}
	}
	return resp.URL, header, nil
}

// withSignedHeaders keeps x-amz-* headers as signed headers instead of hoisting them into the query string.
func withSignedHeaders(o *s3.PresignOptions) {
	o.Presigner = v4.NewSigner(func(so *v4.SignerOptions) {
		so.DisableHeaderHoisting = true
	})
}

// objectKey returns the sharded S3 object key for the given endpoint and OID, or ErrInvalidOID when oid is not a
// SHA-256 hex digest.
func (s *S3) objectKey(endpoint, oid string) (string, error) {
	oid, err := normaliseOID(oid)
	if err != nil {
		return "", err
	}
	return s.prefix + sanitise.Endpoint(endpoint) + "/" + oid[:2] + "/" + oid[2:4] + "/" + oid, nil
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
	respErr, ok := errors.AsType[interface {
		error
		HTTPStatusCode() int
	}](err)
	return ok && respErr.HTTPStatusCode() == 404
}
