# README — Docker Test Image for `validate_image_hash` Integration Test

## Overview

This directory contains the Docker image and instructions used by the
`test_validate_image_hash` integration test.  
The purpose of this test is to verify that the function:

```
validate_image_hash(image_digest, dstack_config, timeout, interval, attempts)
```

correctly:

1. Pulls a Docker image by manifest digest  
2. Verifies its SHA256 config digest  
3. Confirms it matches an approved (hard-coded) value  

This test performs a **real pull from Docker Hub**, so it behaves as a true integration test.

## Test Image Details

A minimal Alpine-based test image was built and uploaded to Docker Hub under:

```
barakeinavnear/launcher-test:1
```

The image’s immutable SHA256 config digest is:

```
sha256:90fded62844519945a8df988437d541c218efdd486d15990fb5ca78ec7f001cd
```

This digest is hard-coded in the test and used to validate correctness.

## How the Image Was Created

### 1. Create a minimal Dockerfile

```Dockerfile
FROM alpine@sha256:765942a4039992336de8dd5db680586e1a206607dd06170ff0a37267a9e01958
CMD ["true"]
```

### 2. Build the image

```bash
docker build -t barakeinavnear/launcher-test:1 .
```

### 3. Push it to Docker Hub

```bash
docker push barakeinavnear/launcher-test:1
```

### 4. Pull it back and extract its digest

```bash
docker pull barakeinavnear/launcher-test:1
docker inspect --format='{{.Id}}' barakeinavnear/launcher-test:1
```

Digest obtained:

```
sha256:90fded62844519945a8df988437d541c218efdd486d15990fb5ca78ec7f001cd
```

## What the Integration Test Does

1. Builds a `dstack_config` that points at this test image.  
2. Calls `validate_image_hash()` with:
   - The expected config digest (sha256:…)
   - Registry info
   - RPC timing values
3. `validate_image_hash()` internally:
   - Resolves image name, tag, and registry
   - Queries Docker Hub for the manifest
   - Fetches the manifest digest
   - Runs `docker pull image@manifestDigest`
   - Runs `docker image inspect` to get the config digest
   - Compares the pulled digest to the expected digest  
4. The test succeeds only when all of the above match.

## Test Dependencies

- Docker installed and running  
- Internet access  
- Docker Hub authentication (recommended)  
- Python: pytest, requests  
- CI runner with Docker access

## Notes & Maintenance

### Test may fail if:
- Docker Hub is down / rate-limiting  
- Image or tag was removed  
- Digest changed  
- CI has no Docker access  

### To update image:
1. Rebuild with new tag  
2. Push  
3. Get new digest  
4. Update test constants  

## Summary

This directory documents the reproducible setup for the integration test ensuring
`validate_image_hash()` works correctly end-to-end with a real Docker registry.
