package grpcserver

import (
	"context"
	"errors"
	"log/slog"

	vaultletv1 "github.com/IbiliAze/vaultlet/api/gen/vaultlet/v1"
	"github.com/IbiliAze/vaultlet/internal/app"
	"github.com/IbiliAze/vaultlet/internal/domain"
	"github.com/IbiliAze/vaultlet/internal/ports"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) GetSecret(ctx context.Context, req *vaultletv1.GetSecretRequest) (*vaultletv1.GetSecretResponse, error) {
	key, err := domain.ParseKey(req.Key)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	secret, err := s.store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, app.ErrPermissionDenied) {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		}

		if errors.Is(err, ports.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "no secret at %s", key)
		}

		slog.ErrorContext(ctx, "get secret", "key", key, "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	meta := secret.Meta()

	return &vaultletv1.GetSecretResponse{Secret: &vaultletv1.Secret{
		Value: secret.Value(),
		Meta: &vaultletv1.SecretMeta{
			Key:       meta.Key.String(),
			Version:   meta.Version.String(),
			CreatedAt: timestamppb.New(meta.CreatedAt),
		}}}, nil
}

func (s *Server) PutSecret(ctx context.Context, req *vaultletv1.PutSecretRequest) (*vaultletv1.PutSecretResponse, error) {
	key, err := domain.ParseKey(req.Key)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if req.ExpectedVersion != nil {
		return nil, status.Error(codes.Unimplemented, "expected_version is not supported")
	}

	meta, err := s.store.Put(ctx, key, req.Value)
	if err != nil {
		if errors.Is(err, app.ErrPermissionDenied) {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		}

		if errors.Is(err, ports.ErrReadOnly) {
			return nil, status.Error(codes.FailedPrecondition, "backend is read-only")
		}

		if errors.Is(err, domain.ErrEmptyValue) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		slog.ErrorContext(ctx, "put secret", "key", key, "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &vaultletv1.PutSecretResponse{Meta: &vaultletv1.SecretMeta{
		Key:       meta.Key.String(),
		Version:   meta.Version.String(),
		CreatedAt: timestamppb.New(meta.CreatedAt),
	}}, nil
}

func (s *Server) ListSecrets(ctx context.Context, req *vaultletv1.ListSecretsRequest) (*vaultletv1.ListSecretsResponse, error) {
	var ns domain.Namespace
	if req.Namespace != "" {
		parsed, err := domain.ParseNamespace(req.Namespace)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		ns = parsed
	}

	if req.PageToken != "" {
		return nil, status.Error(codes.InvalidArgument, "unknown page token")
	}

	metas, err := s.store.List(ctx, ns)
	if err != nil {
		if errors.Is(err, app.ErrPermissionDenied) {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		}

		slog.ErrorContext(ctx, "list secrets", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	out := make([]*vaultletv1.SecretMeta, 0, len(metas))
	for _, meta := range metas {
		out = append(out, &vaultletv1.SecretMeta{
			Key:       meta.Key.String(),
			Version:   meta.Version.String(),
			CreatedAt: timestamppb.New(meta.CreatedAt),
		})
	}

	return &vaultletv1.ListSecretsResponse{Secrets: out}, nil
}

func (s *Server) DeleteSecret(ctx context.Context, req *vaultletv1.DeleteSecretRequest) (*vaultletv1.DeleteSecretResponse, error) {
	key, err := domain.ParseKey(req.Key)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if req.ExpectedVersion != nil {
		return nil, status.Error(codes.Unimplemented, "expected_version is not supported")
	}

	if err := s.store.Delete(ctx, key); err != nil {
		if errors.Is(err, app.ErrPermissionDenied) {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		}

		if errors.Is(err, ports.ErrReadOnly) {
			return nil, status.Error(codes.FailedPrecondition, "backend is read-only")
		}

		if errors.Is(err, ports.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "no secret at %s", key)
		}

		slog.ErrorContext(ctx, "delete secret", "key", key, "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &vaultletv1.DeleteSecretResponse{}, nil
}

func (s *Server) WatchSecrets(req *vaultletv1.WatchSecretsRequest, server grpc.ServerStreamingServer[vaultletv1.WatchSecretsResponse]) error {
	var ns domain.Namespace
	if req.Namespace != "" {
		parsed, err := domain.ParseNamespace(req.Namespace)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		ns = parsed
	}

	ctx := server.Context()

	c, err := s.store.Watch(ctx, ns)
	if err != nil {
		if errors.Is(err, app.ErrPermissionDenied) {
			return status.Error(codes.PermissionDenied, "permission denied")
		}

		slog.ErrorContext(ctx, "watch secrets", "err", err)
		return status.Error(codes.Internal, "internal error")
	}

	for ev := range c {
		var meta *vaultletv1.SecretMeta

		if !isInSync(ev) {
			meta = &vaultletv1.SecretMeta{
				Key:       ev.Meta.Key.String(),
				Version:   ev.Meta.Version.String(),
				CreatedAt: timestamppb.New(ev.Meta.CreatedAt),
			}
		}

		err := server.Send(&vaultletv1.WatchSecretsResponse{
			Event: &vaultletv1.SecretEvent{
				Type: mapEvent(ev.Type),
				Meta: meta,
			},
		})

		if err != nil {
			// A client that hangs up mid-stream is the normal way a watch
			// ends, not a server fault. Report it as a clean return so the
			// logging interceptor records OK rather than an error.
			if ctx.Err() != nil {
				return nil
			}

			slog.ErrorContext(ctx, "watch secrets: send", "err", err)
			return status.Error(codes.Internal, "internal error")
		}
	}

	return nil
}

func isInSync(e domain.SecretEvent) bool {
	return e.Type == domain.InSync
}

func mapEvent(eventType domain.Type) vaultletv1.SecretEventType {
	switch eventType {
	case domain.Added:
		return vaultletv1.SecretEventType_SECRET_EVENT_TYPE_ADDED
	case domain.Updated:
		return vaultletv1.SecretEventType_SECRET_EVENT_TYPE_UPDATED
	case domain.Deleted:
		return vaultletv1.SecretEventType_SECRET_EVENT_TYPE_DELETED
	case domain.InSync:
		return vaultletv1.SecretEventType_SECRET_EVENT_TYPE_IN_SYNC
	}

	return vaultletv1.SecretEventType_SECRET_EVENT_TYPE_UNSPECIFIED
}
