package signingflow

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
)

const maxUploadBytes = 25 * 1024 * 1024

var mimeByExtension = map[string]string{
	".pdf":  "application/pdf",
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".txt":  "text/plain",
	".json": "application/json",
}

// StoredFile is a file that has been uploaded and acknowledged.
type StoredFile struct {
	Name string
	ID   string
}

// FileCreateParams uploads bytes or a path inside UploadRoot. Pass one of File or Path.
type FileCreateParams struct {
	File           []byte
	Path           string
	Filename       string
	MimeType       string
	IdempotencyKey string
}

// Files uploads documents.
type Files struct {
	sender *sender
	cfg    *config
}

// Create stores one file and returns its storage id.
func (f *Files) Create(ctx context.Context, params FileCreateParams) (StoredFile, error) {
	loaded, err := loadFile(params, f.cfg.uploadRoot)
	if err != nil {
		return StoredFile{}, err
	}
	added, err := f.sender.call(ctx, call{
		operation:      operation("StorageService_BatchAddStorage"),
		idempotencyKey: params.IdempotencyKey,
		body: map[string]any{
			"storages": []any{map[string]any{
				"originalName": loaded.filename,
				"displayName":  loaded.filename,
				"size":         strconv.Itoa(len(loaded.bytes)),
				"extension":    loaded.extension,
				"mimeType":     loaded.mimeType,
			}},
		},
	})
	if err != nil {
		return StoredFile{}, err
	}
	name, id, rawURL, ok := findStorage(added)
	if !ok {
		return StoredFile{}, &APIError{info: &info{Message: "Storage did not return an upload URL."}}
	}
	uploadURL, err := allowedUploadURL(rawURL, f.cfg.uploadHosts)
	if err != nil {
		return StoredFile{}, invalid(err.Error())
	}
	if err := f.sender.putBytes(ctx, uploadURL.String(), loaded.mimeType, loaded.bytes); err != nil {
		return StoredFile{}, err
	}
	if _, err := f.sender.call(ctx, call{
		operation: operation("StorageService_BatchAcknowledgeUpload"),
		body:      map[string]any{"names": []any{name}},
	}); err != nil {
		return StoredFile{}, err
	}
	return StoredFile{Name: name, ID: id}, nil
}

type loadedFile struct {
	bytes     []byte
	filename  string
	extension string
	mimeType  string
}

func loadFile(params FileCreateParams, uploadRoot string) (loadedFile, error) {
	hasFile := params.File != nil
	hasPath := strings.TrimSpace(params.Path) != ""
	if hasFile && hasPath {
		return loadedFile{}, invalid("Pass file bytes or a path, not both.")
	}
	if !hasFile && !hasPath {
		return loadedFile{}, invalid("Pass file bytes or a path.")
	}
	var data []byte
	var err error
	if hasFile {
		data = params.File
	} else {
		data, err = readPath(uploadRoot, params.Path)
		if err != nil {
			return loadedFile{}, err
		}
	}
	if int64(len(data)) > maxUploadBytes {
		return loadedFile{}, invalid("The file is larger than 25 MB.")
	}
	filename := strings.TrimSpace(params.Filename)
	if filename == "" && hasPath {
		filename = filepath.Base(params.Path)
	}
	if filename == "" || filename == "." || filename == "/" {
		return loadedFile{}, invalid("filename is required when file is not a path.")
	}
	extension := strings.TrimPrefix(strings.ToLower(filepath.Ext(filename)), ".")
	mimeType := strings.TrimSpace(params.MimeType)
	if mimeType == "" {
		mimeType = mimeByExtension["."+extension]
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	return loadedFile{bytes: data, filename: filename, extension: extension, mimeType: mimeType}, nil
}

func readPath(uploadRoot, requested string) ([]byte, error) {
	if strings.TrimSpace(uploadRoot) == "" {
		return nil, invalid("A filesystem path requires uploadRoot.")
	}
	data, err := readJailed(uploadRoot, requested, maxUploadBytes)
	if err == nil {
		return data, nil
	}
	switch err.Error() {
	case "too large":
		return nil, invalid("The file is larger than 25 MB.")
	case "outside root":
		return nil, invalid("The path is outside uploadRoot.")
	case "hard link":
		return nil, invalid("The file must not be a hard link.")
	default:
		return nil, invalid("The file could not be read.")
	}
}
