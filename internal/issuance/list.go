package issuance

import "encoding/json"

// IssuanceRecordView is one row of GET /oid4vci/v1/issuance's paginated
// listing.
type IssuanceRecordView struct {
	ID             string `json:"id"`
	CredentialType string `json:"credential_type"`
	Status         string `json:"status"`
	SourceType     string `json:"source_type"`
	SourceRef      string `json:"source_ref"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	SubjectName    string `json:"subject_name,omitempty"`
	CredentialData string `json:"credential_data"`
}

// ListIssuanceRecordsResult is GET /oid4vci/v1/issuance's response body.
type ListIssuanceRecordsResult struct {
	Records []IssuanceRecordView `json:"records"`
	Total   int                  `json:"total"`
	Page    int                  `json:"page"`
	Size    int                  `json:"size"`
}

// ListIssuanceRecords returns a page of issuance records, 1-indexed by
// page (matching the Java issuer's offset = (page-1)*size).
func (s *Service) ListIssuanceRecords(page, size int, sort, order string) ListIssuanceRecordsResult {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	offset := (page - 1) * size

	records, total := s.issuances.FindAll(offset, size, sort, order)

	views := make([]IssuanceRecordView, 0, len(records))
	for _, rec := range records {
		views = append(views, IssuanceRecordView{
			ID:             rec.ID,
			CredentialType: rec.CredentialType,
			Status:         rec.Status,
			SourceType:     rec.SourceType,
			SourceRef:      rec.SourceRef,
			CreatedAt:      rec.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			UpdatedAt:      rec.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			SubjectName:    extractSubjectName(rec.CredentialData),
			CredentialData: rec.CredentialData,
		})
	}

	return ListIssuanceRecordsResult{Records: views, Total: total, Page: page, Size: size}
}

// extractSubjectName derives a display name from an issuance record's
// credential_data — PID uses given_name/family_name, matching the Java
// issuer's listIssuanceRecords (its Student ID firstName/familyName
// fallback is dropped here since Student ID isn't issued by this port).
func extractSubjectName(credentialDataJSON string) string {
	var data map[string]any
	if err := json.Unmarshal([]byte(credentialDataJSON), &data); err != nil {
		return ""
	}
	given, _ := data["given_name"].(string)
	family, _ := data["family_name"].(string)
	switch {
	case given != "" && family != "":
		return given + " " + family
	case given != "":
		return given
	case family != "":
		return family
	default:
		return ""
	}
}
