package domain

type Type string

const (
	Added   Type = "added"
	Updated Type = "updated"
	Deleted Type = "deleted"
	InSync  Type = "inSync"
)

type SecretEvent struct {
	Type
	Meta SecretMeta
}
