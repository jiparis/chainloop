// Code generated by ent, DO NOT EDIT.

package workflowcontractversion

import (
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/unmarshal"
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the workflowcontractversion type in the database.
	Label = "workflow_contract_version"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldBody holds the string denoting the body field in the database.
	FieldBody = "body"
	// FieldRawBody holds the string denoting the raw_body field in the database.
	FieldRawBody = "raw_body"
	// FieldRawBodyFormat holds the string denoting the raw_body_format field in the database.
	FieldRawBodyFormat = "raw_body_format"
	// FieldRevision holds the string denoting the revision field in the database.
	FieldRevision = "revision"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// EdgeContract holds the string denoting the contract edge name in mutations.
	EdgeContract = "contract"
	// Table holds the table name of the workflowcontractversion in the database.
	Table = "workflow_contract_versions"
	// ContractTable is the table that holds the contract relation/edge.
	ContractTable = "workflow_contract_versions"
	// ContractInverseTable is the table name for the WorkflowContract entity.
	// It exists in this package in order to avoid circular dependency with the "workflowcontract" package.
	ContractInverseTable = "workflow_contracts"
	// ContractColumn is the table column denoting the contract relation/edge.
	ContractColumn = "workflow_contract_versions"
)

// Columns holds all SQL columns for workflowcontractversion fields.
var Columns = []string{
	FieldID,
	FieldBody,
	FieldRawBody,
	FieldRawBodyFormat,
	FieldRevision,
	FieldCreatedAt,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "workflow_contract_versions"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"workflow_contract_versions",
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// RawBodyValidator is a validator for the "raw_body" field. It is called by the builders before save.
	RawBodyValidator func([]byte) error
	// DefaultRevision holds the default value on creation for the "revision" field.
	DefaultRevision int
	// DefaultCreatedAt holds the default value on creation for the "created_at" field.
	DefaultCreatedAt func() time.Time
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)

// RawBodyFormatValidator is a validator for the "raw_body_format" field enum values. It is called by the builders before save.
func RawBodyFormatValidator(rbf unmarshal.RawFormat) error {
	switch rbf {
	case "json", "yaml", "cue":
		return nil
	default:
		return fmt.Errorf("workflowcontractversion: invalid enum value for raw_body_format field: %q", rbf)
	}
}

// OrderOption defines the ordering options for the WorkflowContractVersion queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByRawBodyFormat orders the results by the raw_body_format field.
func ByRawBodyFormat(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldRawBodyFormat, opts...).ToFunc()
}

// ByRevision orders the results by the revision field.
func ByRevision(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldRevision, opts...).ToFunc()
}

// ByCreatedAt orders the results by the created_at field.
func ByCreatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCreatedAt, opts...).ToFunc()
}

// ByContractField orders the results by contract field.
func ByContractField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newContractStep(), sql.OrderByField(field, opts...))
	}
}
func newContractStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(ContractInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, ContractTable, ContractColumn),
	)
}
