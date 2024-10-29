package main

import (
    "bytes"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "os"
    "strings"
    "crypto/sha256"
    "encoding/hex"
)

type Manifest struct {
    SchemaVersion int               `json:"schemaVersion"`
    MediaType     string            `json:"mediaType"`
    Config        Descriptor        `json:"config"`
    Layers        []Descriptor      `json:"layers"`
    Digest        string            `json:"-"`
    Size          int64             `json:"-"`
    Platform      map[string]string `json:"-"`
}

type Descriptor struct {
    MediaType string `json:"mediaType"`
    Size      int64  `json:"size"`
    Digest    string `json:"digest"`
}

type ManifestList struct {
    SchemaVersion int          `json:"schemaVersion"`
    MediaType     string       `json:"mediaType"`
    Manifests     []ManifestMD `json:"manifests"`
}

type ManifestMD struct {
    MediaType string            `json:"mediaType"`
    Size      int64             `json:"size"`
    Digest    string            `json:"digest"`
    Platform  map[string]string `json:"platform"`
}

func main() {
    var username, password string
    flag.StringVar(&username, "u", "", "Registry username")
    flag.StringVar(&password, "p", "", "Registry password")
    flag.Parse()

    args := flag.Args()
    if len(args) < 2 {
        fmt.Printf("Usage: %s [-u username] [-p password] destination_image source_image1 source_image2 ...\n", os.Args[0])
        os.Exit(1)
    }

    destImage := args[0]
    srcImages := args[1:]

    // Collect manifests from source images
    var manifests []ManifestMD
    tokens := make(map[string]string) // registry -> token

    for _, srcImage := range srcImages {
        fmt.Printf("Processing source image: %s\n", srcImage)
        registry, repository, reference := parseImage(srcImage)
        token, ok := tokens[registry]
        if !ok {
            var err error
            token, err = getAuthToken(registry, repository, username, password)
            if err != nil {
                log.Fatalf("Error getting auth token: %v", err)
            }
            tokens[registry] = token
        }

        manifestBytes, manifest, err := getManifest(registry, repository, reference, token)
        if err != nil {
            log.Fatalf("Error getting manifest for %s: %v", srcImage, err)
        }

        configBlob, err := getConfigBlob(registry, repository, manifest.Config.Digest, token)
        if err != nil {
            log.Fatalf("Error getting config blob for %s: %v", srcImage, err)
        }

        platform, err := getPlatformInfo(configBlob)
        if err != nil {
            log.Fatalf("Error getting platform info for %s: %v", srcImage, err)
        }

        // Push the manifest to the destination repository if necessary
        destRegistry, destRepository, _:= parseImage(destImage)
        if repository != destRepository || registry != destRegistry {
            fmt.Printf("Copying manifest from %s to %s\n", srcImage, destRepository)
            destToken, ok := tokens[destRegistry]
            if !ok {
                destToken, err = getAuthToken(destRegistry, destRepository, username, password)
                if err != nil {
                    log.Fatalf("Error getting auth token for destination registry: %v", err)
                }
                tokens[destRegistry] = destToken
            }
            // Push the manifest and its layers to the destination repository
            err = pushManifestAndLayers(destRegistry, destRepository, reference, destToken, manifestBytes, manifest)
            if err != nil {
                log.Fatalf("Error pushing manifest and layers: %v", err)
            }
            registry = destRegistry
            repository = destRepository
        }

        manifests = append(manifests, ManifestMD{
            MediaType: manifest.MediaType,
            Size:      manifest.Size,
            Digest:    manifest.Digest,
            Platform:  platform,
        })
    }

    // Create manifest list
    manifestList := ManifestList{
        SchemaVersion: 2,
        MediaType:     "application/vnd.docker.distribution.manifest.list.v2+json",
        Manifests:     manifests,
    }

    manifestListBytes, err := json.Marshal(manifestList)
    if err != nil {
        log.Fatalf("Error marshalling manifest list: %v", err)
    }

    // Push manifest list to destination image
    fmt.Printf("Pushing manifest list to %s\n", destImage)
    registry, repository, reference := parseImage(destImage)
    token, ok := tokens[registry]
    if !ok {
        token, err = getAuthToken(registry, repository, username, password)
        if err != nil {
            log.Fatalf("Error getting auth token: %v", err)
        }
        tokens[registry] = token
    }

    err = putManifestList(registry, repository, reference, token, manifestListBytes)
    if err != nil {
        log.Fatalf("Error pushing manifest list: %v", err)
    }

    fmt.Printf("Successfully pushed multi-arch image to %s\n", destImage)
}

// Modify getManifest to return manifestBytes
func getManifest(registry, repository, reference, token string) ([]byte, *Manifest, error) {
    url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, reference)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, nil, err
    }
    req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, nil, fmt.Errorf("failed to get manifest: %s", string(body))
    }

    manifestBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, nil, err
    }

    manifest := &Manifest{}
    err = json.Unmarshal(manifestBytes, manifest)
    if err != nil {
        return nil, nil, err
    }

    // Compute digest
    h := sha256.New()
    h.Write(manifestBytes)
    manifest.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
    manifest.Size = int64(len(manifestBytes))
    manifest.MediaType = resp.Header.Get("Content-Type")
    if manifest.MediaType == "" {
        manifest.MediaType = "application/vnd.docker.distribution.manifest.v2+json"
    }

    return manifestBytes, manifest, nil
}

// Add a new function to push the manifest and layers to the destination repository
func pushManifestAndLayers(registry, repository, reference, token string, manifestBytes []byte, manifest *Manifest) error {
    // Push layers
    for _, layer := range append([]Descriptor{manifest.Config}, manifest.Layers...) {
        err := checkBlobExists(registry, repository, layer.Digest, token)
        if err == nil {
            continue // Blob already exists
        }
        // Fetch blob from source
        blobData, err := getBlob(registry, repository, layer.Digest, token)
        if err != nil {
            return fmt.Errorf("failed to get blob %s: %v", layer.Digest, err)
        }
        // Upload blob to destination
        err = uploadBlob(registry, repository, layer.Digest, blobData, token)
        if err != nil {
            return fmt.Errorf("failed to upload blob %s: %v", layer.Digest, err)
        }
    }

    // Push manifest
    url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, manifest.Digest)
    req, err := http.NewRequest("PUT", url, bytes.NewReader(manifestBytes))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", manifest.MediaType)
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("failed to push manifest: %s", string(body))
    }

    return nil
}

// Add helper functions to check blob existence, get blob, and upload blob

func checkBlobExists(registry, repository, digest, token string) error {
    url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, digest)
    req, err := http.NewRequest("HEAD", url, nil)
    if err != nil {
        return err
    }
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusOK {
        return nil
    }
    return fmt.Errorf("blob does not exist")
}

func getBlob(registry, repository, digest, token string) ([]byte, error) {
    url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, digest)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("failed to get blob: %s", string(body))
    }

    return io.ReadAll(resp.Body)
}

func uploadBlob(registry, repository, digest string, data []byte, token string) error {
    // Start a blob upload
    startURL := fmt.Sprintf("https://%s/v2/%s/blobs/uploads/", registry, repository)
    req, err := http.NewRequest("POST", startURL, nil)
    if err != nil {
        return err
    }
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusAccepted {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("failed to start blob upload: %s", string(body))
    }

    uploadURL := resp.Header.Get("Location")
    if uploadURL == "" {
        return fmt.Errorf("missing upload location")
    }

    // Complete the upload with the data
    uploadURL = uploadURL + fmt.Sprintf("&digest=%s", digest)
    req, err = http.NewRequest("PUT", uploadURL, bytes.NewReader(data))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/octet-stream")
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

    resp, err = http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusCreated {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("failed to upload blob: %s", string(body))
    }

    return nil
}

func parseImage(image string) (registry, repository, reference string) {
    if !strings.Contains(image, "/") {
        image = "library/" + image
    }

    parts := strings.SplitN(image, "/", 2)
    if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
        registry = parts[0]
        repository = parts[1]
    } else {
        registry = "registry-1.docker.io"
        repository = image
    }

    if strings.Contains(repository, "@") {
        subParts := strings.SplitN(repository, "@", 2)
        repository = subParts[0]
        reference = subParts[1]
    } else if strings.Contains(repository, ":") {
        subParts := strings.SplitN(repository, ":", 2)
        repository = subParts[0]
        reference = subParts[1]
    } else {
        reference = "latest"
    }

    return
}

func getAuthToken(registry, repository, username, password string) (string, error) {
    // Get authentication challenge
    endpointURL := fmt.Sprintf("https://%s/v2/", registry)
    req, err := http.NewRequest("GET", endpointURL, nil)
    if err != nil {
        return "", err
    }
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusUnauthorized {
        return "", fmt.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
    }

    authHeader := resp.Header.Get("WWW-Authenticate")
    if !strings.HasPrefix(authHeader, "Bearer ") {
        return "", fmt.Errorf("unsupported auth scheme: %s", authHeader)
    }

    params := parseAuthHeader(authHeader[len("Bearer "):])
    realm := params["realm"]
    service := params["service"]
    scope := fmt.Sprintf("repository:%s:pull,push", repository)

    // Request token
    tokenURL := fmt.Sprintf("%s?service=%s&scope=%s", realm, url.QueryEscape(service), url.QueryEscape(scope))
    req, err = http.NewRequest("GET", tokenURL, nil)
    if err != nil {
        return "", err
    }
    if username != "" && password != "" {
        req.SetBasicAuth(username, password)
    }
    resp, err = http.DefaultClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return "", fmt.Errorf("failed to get token: %s", string(body))
    }

    var tokenResponse struct {
        Token string `json:"token"`
    }
    err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
    if err != nil {
        return "", err
    }

    return tokenResponse.Token, nil
}

func parseAuthHeader(header string) map[string]string {
    params := make(map[string]string)
    for _, part := range strings.Split(header, ",") {
        kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
        if len(kv) == 2 {
            key := kv[0]
            value := strings.Trim(kv[1], `"`)
            params[key] = value
        }
    }
    return params
}

func getConfigBlob(registry, repository, digest, token string) ([]byte, error) {
    url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, digest)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("failed to get config blob: %s", string(body))
    }

    return io.ReadAll(resp.Body)
}

func getPlatformInfo(configBlob []byte) (map[string]string, error) {
    var config struct {
        Architecture string `json:"architecture"`
        OS           string `json:"os"`
        Variant      string `json:"variant,omitempty"`
    }

    err := json.Unmarshal(configBlob, &config)
    if err != nil {
        return nil, err
    }

    platform := map[string]string{
        "architecture": config.Architecture,
        "os":           config.OS,
    }

    if config.Variant != "" {
        platform["variant"] = config.Variant
    }

    return platform, nil
}

func putManifestList(registry, repository, reference, token string, manifestList []byte) error {
    url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, reference)
    req, err := http.NewRequest("PUT", url, bytes.NewReader(manifestList))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.list.v2+json")
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("failed to push manifest list: %s", string(body))
    }

    return nil
}
