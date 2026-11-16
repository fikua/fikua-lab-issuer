// Package audit emits the audit events of the Fikua Lab credential issuer and
// counts its business operations (Fikua observability convention, OBS-09 and
// OBS-12). The platform Collector archives the events, locked, for five years;
// the catalogue was reviewed on 2026-11-16 (Oriol Canadés):
//
//	event.name          when                                   attributes
//	issuance.created    an issuance record and its offer exist   issuance.id, scheme.id
//	credential.issued   a credential was signed for the wallet    issuance.id, scheme.id, format
//	credential.revoked  an issued credential was revoked         issuance.id
//	auth.rejected       a credential request was refused         reason (the OAuth2 error code)
//
// Never the credential data, a token, a proof or an IP address.
package audit

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
)

const (
	scope       = "fikua-lab-issuer/audit"
	counterName = "issuer.business.operations"
)

func IssuanceCreated(ctx context.Context, issuanceID, schemeID string) {
	Emit(ctx, "issuance.created", attribute.String("issuance.id", issuanceID), attribute.String("scheme.id", schemeID))
	Count(ctx, "issuance.create", "success", "")
}

func CredentialIssued(ctx context.Context, issuanceID, schemeID, format string) {
	Emit(ctx, "credential.issued", attribute.String("issuance.id", issuanceID),
		attribute.String("scheme.id", schemeID), attribute.String("format", format))
	Count(ctx, "credential.issue", "success", "")
}

func CredentialRevoked(ctx context.Context, issuanceID string) {
	Emit(ctx, "credential.revoked", attribute.String("issuance.id", issuanceID))
	Count(ctx, "credential.revoke", "success", "")
}

// CredentialRejected records a refused credential request with its OAuth2 error code.
func CredentialRejected(ctx context.Context, reason string) {
	Emit(ctx, "auth.rejected", attribute.String("reason", reason))
	Count(ctx, "credential.issue", "rejected", reason)
}

// Emit sends one audit event: an OpenTelemetry log record with
// event.domain = audit and the catalogue attributes. It never fails the caller.
func Emit(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	var r log.Record
	r.SetSeverity(log.SeverityInfo)
	r.SetSeverityText("INFO")
	r.SetBody(attribute.StringValue(name))
	r.AddAttributes(attribute.String("event.domain", "audit"), attribute.String("event.name", name))
	r.AddAttributes(attrs...)
	global.GetLoggerProvider().Logger(scope).Emit(ctx, r)
}

var (
	counterOnce sync.Once
	counter     metric.Int64Counter
)

// Count adds one business operation to the service's counter (OBS-09).
// errorType is set only when the operation failed or was refused.
func Count(ctx context.Context, operation, outcome, errorType string) {
	counterOnce.Do(func() {
		counter, _ = otel.GetMeterProvider().Meter(scope).Int64Counter(counterName,
			metric.WithDescription("Business operations, by operation and outcome"),
			metric.WithUnit("{operation}"))
	})
	if counter == nil {
		return
	}
	attrs := []attribute.KeyValue{attribute.String("operation", operation), attribute.String("outcome", outcome)}
	if errorType != "" {
		attrs = append(attrs, attribute.String("error.type", errorType))
	}
	counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}
