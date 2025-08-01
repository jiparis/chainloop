// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/authz"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/membership"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/organization"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/data/ent/user"
	"github.com/google/uuid"
)

// MembershipCreate is the builder for creating a Membership entity.
type MembershipCreate struct {
	config
	mutation *MembershipMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetCurrent sets the "current" field.
func (mc *MembershipCreate) SetCurrent(b bool) *MembershipCreate {
	mc.mutation.SetCurrent(b)
	return mc
}

// SetNillableCurrent sets the "current" field if the given value is not nil.
func (mc *MembershipCreate) SetNillableCurrent(b *bool) *MembershipCreate {
	if b != nil {
		mc.SetCurrent(*b)
	}
	return mc
}

// SetCreatedAt sets the "created_at" field.
func (mc *MembershipCreate) SetCreatedAt(t time.Time) *MembershipCreate {
	mc.mutation.SetCreatedAt(t)
	return mc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (mc *MembershipCreate) SetNillableCreatedAt(t *time.Time) *MembershipCreate {
	if t != nil {
		mc.SetCreatedAt(*t)
	}
	return mc
}

// SetUpdatedAt sets the "updated_at" field.
func (mc *MembershipCreate) SetUpdatedAt(t time.Time) *MembershipCreate {
	mc.mutation.SetUpdatedAt(t)
	return mc
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (mc *MembershipCreate) SetNillableUpdatedAt(t *time.Time) *MembershipCreate {
	if t != nil {
		mc.SetUpdatedAt(*t)
	}
	return mc
}

// SetRole sets the "role" field.
func (mc *MembershipCreate) SetRole(a authz.Role) *MembershipCreate {
	mc.mutation.SetRole(a)
	return mc
}

// SetMembershipType sets the "membership_type" field.
func (mc *MembershipCreate) SetMembershipType(at authz.MembershipType) *MembershipCreate {
	mc.mutation.SetMembershipType(at)
	return mc
}

// SetNillableMembershipType sets the "membership_type" field if the given value is not nil.
func (mc *MembershipCreate) SetNillableMembershipType(at *authz.MembershipType) *MembershipCreate {
	if at != nil {
		mc.SetMembershipType(*at)
	}
	return mc
}

// SetMemberID sets the "member_id" field.
func (mc *MembershipCreate) SetMemberID(u uuid.UUID) *MembershipCreate {
	mc.mutation.SetMemberID(u)
	return mc
}

// SetNillableMemberID sets the "member_id" field if the given value is not nil.
func (mc *MembershipCreate) SetNillableMemberID(u *uuid.UUID) *MembershipCreate {
	if u != nil {
		mc.SetMemberID(*u)
	}
	return mc
}

// SetResourceType sets the "resource_type" field.
func (mc *MembershipCreate) SetResourceType(at authz.ResourceType) *MembershipCreate {
	mc.mutation.SetResourceType(at)
	return mc
}

// SetNillableResourceType sets the "resource_type" field if the given value is not nil.
func (mc *MembershipCreate) SetNillableResourceType(at *authz.ResourceType) *MembershipCreate {
	if at != nil {
		mc.SetResourceType(*at)
	}
	return mc
}

// SetResourceID sets the "resource_id" field.
func (mc *MembershipCreate) SetResourceID(u uuid.UUID) *MembershipCreate {
	mc.mutation.SetResourceID(u)
	return mc
}

// SetNillableResourceID sets the "resource_id" field if the given value is not nil.
func (mc *MembershipCreate) SetNillableResourceID(u *uuid.UUID) *MembershipCreate {
	if u != nil {
		mc.SetResourceID(*u)
	}
	return mc
}

// SetParentID sets the "parent_id" field.
func (mc *MembershipCreate) SetParentID(u uuid.UUID) *MembershipCreate {
	mc.mutation.SetParentID(u)
	return mc
}

// SetNillableParentID sets the "parent_id" field if the given value is not nil.
func (mc *MembershipCreate) SetNillableParentID(u *uuid.UUID) *MembershipCreate {
	if u != nil {
		mc.SetParentID(*u)
	}
	return mc
}

// SetID sets the "id" field.
func (mc *MembershipCreate) SetID(u uuid.UUID) *MembershipCreate {
	mc.mutation.SetID(u)
	return mc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (mc *MembershipCreate) SetNillableID(u *uuid.UUID) *MembershipCreate {
	if u != nil {
		mc.SetID(*u)
	}
	return mc
}

// SetOrganizationID sets the "organization" edge to the Organization entity by ID.
func (mc *MembershipCreate) SetOrganizationID(id uuid.UUID) *MembershipCreate {
	mc.mutation.SetOrganizationID(id)
	return mc
}

// SetNillableOrganizationID sets the "organization" edge to the Organization entity by ID if the given value is not nil.
func (mc *MembershipCreate) SetNillableOrganizationID(id *uuid.UUID) *MembershipCreate {
	if id != nil {
		mc = mc.SetOrganizationID(*id)
	}
	return mc
}

// SetOrganization sets the "organization" edge to the Organization entity.
func (mc *MembershipCreate) SetOrganization(o *Organization) *MembershipCreate {
	return mc.SetOrganizationID(o.ID)
}

// SetUserID sets the "user" edge to the User entity by ID.
func (mc *MembershipCreate) SetUserID(id uuid.UUID) *MembershipCreate {
	mc.mutation.SetUserID(id)
	return mc
}

// SetNillableUserID sets the "user" edge to the User entity by ID if the given value is not nil.
func (mc *MembershipCreate) SetNillableUserID(id *uuid.UUID) *MembershipCreate {
	if id != nil {
		mc = mc.SetUserID(*id)
	}
	return mc
}

// SetUser sets the "user" edge to the User entity.
func (mc *MembershipCreate) SetUser(u *User) *MembershipCreate {
	return mc.SetUserID(u.ID)
}

// SetParent sets the "parent" edge to the Membership entity.
func (mc *MembershipCreate) SetParent(m *Membership) *MembershipCreate {
	return mc.SetParentID(m.ID)
}

// AddChildIDs adds the "children" edge to the Membership entity by IDs.
func (mc *MembershipCreate) AddChildIDs(ids ...uuid.UUID) *MembershipCreate {
	mc.mutation.AddChildIDs(ids...)
	return mc
}

// AddChildren adds the "children" edges to the Membership entity.
func (mc *MembershipCreate) AddChildren(m ...*Membership) *MembershipCreate {
	ids := make([]uuid.UUID, len(m))
	for i := range m {
		ids[i] = m[i].ID
	}
	return mc.AddChildIDs(ids...)
}

// Mutation returns the MembershipMutation object of the builder.
func (mc *MembershipCreate) Mutation() *MembershipMutation {
	return mc.mutation
}

// Save creates the Membership in the database.
func (mc *MembershipCreate) Save(ctx context.Context) (*Membership, error) {
	mc.defaults()
	return withHooks(ctx, mc.sqlSave, mc.mutation, mc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (mc *MembershipCreate) SaveX(ctx context.Context) *Membership {
	v, err := mc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (mc *MembershipCreate) Exec(ctx context.Context) error {
	_, err := mc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (mc *MembershipCreate) ExecX(ctx context.Context) {
	if err := mc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (mc *MembershipCreate) defaults() {
	if _, ok := mc.mutation.Current(); !ok {
		v := membership.DefaultCurrent
		mc.mutation.SetCurrent(v)
	}
	if _, ok := mc.mutation.CreatedAt(); !ok {
		v := membership.DefaultCreatedAt()
		mc.mutation.SetCreatedAt(v)
	}
	if _, ok := mc.mutation.UpdatedAt(); !ok {
		v := membership.DefaultUpdatedAt()
		mc.mutation.SetUpdatedAt(v)
	}
	if _, ok := mc.mutation.ID(); !ok {
		v := membership.DefaultID()
		mc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (mc *MembershipCreate) check() error {
	if _, ok := mc.mutation.Current(); !ok {
		return &ValidationError{Name: "current", err: errors.New(`ent: missing required field "Membership.current"`)}
	}
	if _, ok := mc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "Membership.created_at"`)}
	}
	if _, ok := mc.mutation.UpdatedAt(); !ok {
		return &ValidationError{Name: "updated_at", err: errors.New(`ent: missing required field "Membership.updated_at"`)}
	}
	if _, ok := mc.mutation.Role(); !ok {
		return &ValidationError{Name: "role", err: errors.New(`ent: missing required field "Membership.role"`)}
	}
	if v, ok := mc.mutation.Role(); ok {
		if err := membership.RoleValidator(v); err != nil {
			return &ValidationError{Name: "role", err: fmt.Errorf(`ent: validator failed for field "Membership.role": %w`, err)}
		}
	}
	if v, ok := mc.mutation.MembershipType(); ok {
		if err := membership.MembershipTypeValidator(v); err != nil {
			return &ValidationError{Name: "membership_type", err: fmt.Errorf(`ent: validator failed for field "Membership.membership_type": %w`, err)}
		}
	}
	if v, ok := mc.mutation.ResourceType(); ok {
		if err := membership.ResourceTypeValidator(v); err != nil {
			return &ValidationError{Name: "resource_type", err: fmt.Errorf(`ent: validator failed for field "Membership.resource_type": %w`, err)}
		}
	}
	return nil
}

func (mc *MembershipCreate) sqlSave(ctx context.Context) (*Membership, error) {
	if err := mc.check(); err != nil {
		return nil, err
	}
	_node, _spec := mc.createSpec()
	if err := sqlgraph.CreateNode(ctx, mc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(*uuid.UUID); ok {
			_node.ID = *id
		} else if err := _node.ID.Scan(_spec.ID.Value); err != nil {
			return nil, err
		}
	}
	mc.mutation.id = &_node.ID
	mc.mutation.done = true
	return _node, nil
}

func (mc *MembershipCreate) createSpec() (*Membership, *sqlgraph.CreateSpec) {
	var (
		_node = &Membership{config: mc.config}
		_spec = sqlgraph.NewCreateSpec(membership.Table, sqlgraph.NewFieldSpec(membership.FieldID, field.TypeUUID))
	)
	_spec.OnConflict = mc.conflict
	if id, ok := mc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := mc.mutation.Current(); ok {
		_spec.SetField(membership.FieldCurrent, field.TypeBool, value)
		_node.Current = value
	}
	if value, ok := mc.mutation.CreatedAt(); ok {
		_spec.SetField(membership.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := mc.mutation.UpdatedAt(); ok {
		_spec.SetField(membership.FieldUpdatedAt, field.TypeTime, value)
		_node.UpdatedAt = value
	}
	if value, ok := mc.mutation.Role(); ok {
		_spec.SetField(membership.FieldRole, field.TypeEnum, value)
		_node.Role = value
	}
	if value, ok := mc.mutation.MembershipType(); ok {
		_spec.SetField(membership.FieldMembershipType, field.TypeEnum, value)
		_node.MembershipType = value
	}
	if value, ok := mc.mutation.MemberID(); ok {
		_spec.SetField(membership.FieldMemberID, field.TypeUUID, value)
		_node.MemberID = value
	}
	if value, ok := mc.mutation.ResourceType(); ok {
		_spec.SetField(membership.FieldResourceType, field.TypeEnum, value)
		_node.ResourceType = value
	}
	if value, ok := mc.mutation.ResourceID(); ok {
		_spec.SetField(membership.FieldResourceID, field.TypeUUID, value)
		_node.ResourceID = value
	}
	if nodes := mc.mutation.OrganizationIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   membership.OrganizationTable,
			Columns: []string{membership.OrganizationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(organization.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.organization_memberships = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := mc.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   membership.UserTable,
			Columns: []string{membership.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.user_memberships = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := mc.mutation.ParentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   membership.ParentTable,
			Columns: []string{membership.ParentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(membership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.ParentID = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := mc.mutation.ChildrenIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   membership.ChildrenTable,
			Columns: []string{membership.ChildrenColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(membership.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Membership.Create().
//		SetCurrent(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.MembershipUpsert) {
//			SetCurrent(v+v).
//		}).
//		Exec(ctx)
func (mc *MembershipCreate) OnConflict(opts ...sql.ConflictOption) *MembershipUpsertOne {
	mc.conflict = opts
	return &MembershipUpsertOne{
		create: mc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Membership.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (mc *MembershipCreate) OnConflictColumns(columns ...string) *MembershipUpsertOne {
	mc.conflict = append(mc.conflict, sql.ConflictColumns(columns...))
	return &MembershipUpsertOne{
		create: mc,
	}
}

type (
	// MembershipUpsertOne is the builder for "upsert"-ing
	//  one Membership node.
	MembershipUpsertOne struct {
		create *MembershipCreate
	}

	// MembershipUpsert is the "OnConflict" setter.
	MembershipUpsert struct {
		*sql.UpdateSet
	}
)

// SetCurrent sets the "current" field.
func (u *MembershipUpsert) SetCurrent(v bool) *MembershipUpsert {
	u.Set(membership.FieldCurrent, v)
	return u
}

// UpdateCurrent sets the "current" field to the value that was provided on create.
func (u *MembershipUpsert) UpdateCurrent() *MembershipUpsert {
	u.SetExcluded(membership.FieldCurrent)
	return u
}

// SetUpdatedAt sets the "updated_at" field.
func (u *MembershipUpsert) SetUpdatedAt(v time.Time) *MembershipUpsert {
	u.Set(membership.FieldUpdatedAt, v)
	return u
}

// UpdateUpdatedAt sets the "updated_at" field to the value that was provided on create.
func (u *MembershipUpsert) UpdateUpdatedAt() *MembershipUpsert {
	u.SetExcluded(membership.FieldUpdatedAt)
	return u
}

// SetRole sets the "role" field.
func (u *MembershipUpsert) SetRole(v authz.Role) *MembershipUpsert {
	u.Set(membership.FieldRole, v)
	return u
}

// UpdateRole sets the "role" field to the value that was provided on create.
func (u *MembershipUpsert) UpdateRole() *MembershipUpsert {
	u.SetExcluded(membership.FieldRole)
	return u
}

// SetMembershipType sets the "membership_type" field.
func (u *MembershipUpsert) SetMembershipType(v authz.MembershipType) *MembershipUpsert {
	u.Set(membership.FieldMembershipType, v)
	return u
}

// UpdateMembershipType sets the "membership_type" field to the value that was provided on create.
func (u *MembershipUpsert) UpdateMembershipType() *MembershipUpsert {
	u.SetExcluded(membership.FieldMembershipType)
	return u
}

// ClearMembershipType clears the value of the "membership_type" field.
func (u *MembershipUpsert) ClearMembershipType() *MembershipUpsert {
	u.SetNull(membership.FieldMembershipType)
	return u
}

// SetMemberID sets the "member_id" field.
func (u *MembershipUpsert) SetMemberID(v uuid.UUID) *MembershipUpsert {
	u.Set(membership.FieldMemberID, v)
	return u
}

// UpdateMemberID sets the "member_id" field to the value that was provided on create.
func (u *MembershipUpsert) UpdateMemberID() *MembershipUpsert {
	u.SetExcluded(membership.FieldMemberID)
	return u
}

// ClearMemberID clears the value of the "member_id" field.
func (u *MembershipUpsert) ClearMemberID() *MembershipUpsert {
	u.SetNull(membership.FieldMemberID)
	return u
}

// SetResourceType sets the "resource_type" field.
func (u *MembershipUpsert) SetResourceType(v authz.ResourceType) *MembershipUpsert {
	u.Set(membership.FieldResourceType, v)
	return u
}

// UpdateResourceType sets the "resource_type" field to the value that was provided on create.
func (u *MembershipUpsert) UpdateResourceType() *MembershipUpsert {
	u.SetExcluded(membership.FieldResourceType)
	return u
}

// ClearResourceType clears the value of the "resource_type" field.
func (u *MembershipUpsert) ClearResourceType() *MembershipUpsert {
	u.SetNull(membership.FieldResourceType)
	return u
}

// SetResourceID sets the "resource_id" field.
func (u *MembershipUpsert) SetResourceID(v uuid.UUID) *MembershipUpsert {
	u.Set(membership.FieldResourceID, v)
	return u
}

// UpdateResourceID sets the "resource_id" field to the value that was provided on create.
func (u *MembershipUpsert) UpdateResourceID() *MembershipUpsert {
	u.SetExcluded(membership.FieldResourceID)
	return u
}

// ClearResourceID clears the value of the "resource_id" field.
func (u *MembershipUpsert) ClearResourceID() *MembershipUpsert {
	u.SetNull(membership.FieldResourceID)
	return u
}

// SetParentID sets the "parent_id" field.
func (u *MembershipUpsert) SetParentID(v uuid.UUID) *MembershipUpsert {
	u.Set(membership.FieldParentID, v)
	return u
}

// UpdateParentID sets the "parent_id" field to the value that was provided on create.
func (u *MembershipUpsert) UpdateParentID() *MembershipUpsert {
	u.SetExcluded(membership.FieldParentID)
	return u
}

// ClearParentID clears the value of the "parent_id" field.
func (u *MembershipUpsert) ClearParentID() *MembershipUpsert {
	u.SetNull(membership.FieldParentID)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.Membership.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(membership.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *MembershipUpsertOne) UpdateNewValues() *MembershipUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(membership.FieldID)
		}
		if _, exists := u.create.mutation.CreatedAt(); exists {
			s.SetIgnore(membership.FieldCreatedAt)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Membership.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *MembershipUpsertOne) Ignore() *MembershipUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *MembershipUpsertOne) DoNothing() *MembershipUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the MembershipCreate.OnConflict
// documentation for more info.
func (u *MembershipUpsertOne) Update(set func(*MembershipUpsert)) *MembershipUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&MembershipUpsert{UpdateSet: update})
	}))
	return u
}

// SetCurrent sets the "current" field.
func (u *MembershipUpsertOne) SetCurrent(v bool) *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.SetCurrent(v)
	})
}

// UpdateCurrent sets the "current" field to the value that was provided on create.
func (u *MembershipUpsertOne) UpdateCurrent() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateCurrent()
	})
}

// SetUpdatedAt sets the "updated_at" field.
func (u *MembershipUpsertOne) SetUpdatedAt(v time.Time) *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.SetUpdatedAt(v)
	})
}

// UpdateUpdatedAt sets the "updated_at" field to the value that was provided on create.
func (u *MembershipUpsertOne) UpdateUpdatedAt() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateUpdatedAt()
	})
}

// SetRole sets the "role" field.
func (u *MembershipUpsertOne) SetRole(v authz.Role) *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.SetRole(v)
	})
}

// UpdateRole sets the "role" field to the value that was provided on create.
func (u *MembershipUpsertOne) UpdateRole() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateRole()
	})
}

// SetMembershipType sets the "membership_type" field.
func (u *MembershipUpsertOne) SetMembershipType(v authz.MembershipType) *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.SetMembershipType(v)
	})
}

// UpdateMembershipType sets the "membership_type" field to the value that was provided on create.
func (u *MembershipUpsertOne) UpdateMembershipType() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateMembershipType()
	})
}

// ClearMembershipType clears the value of the "membership_type" field.
func (u *MembershipUpsertOne) ClearMembershipType() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearMembershipType()
	})
}

// SetMemberID sets the "member_id" field.
func (u *MembershipUpsertOne) SetMemberID(v uuid.UUID) *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.SetMemberID(v)
	})
}

// UpdateMemberID sets the "member_id" field to the value that was provided on create.
func (u *MembershipUpsertOne) UpdateMemberID() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateMemberID()
	})
}

// ClearMemberID clears the value of the "member_id" field.
func (u *MembershipUpsertOne) ClearMemberID() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearMemberID()
	})
}

// SetResourceType sets the "resource_type" field.
func (u *MembershipUpsertOne) SetResourceType(v authz.ResourceType) *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.SetResourceType(v)
	})
}

// UpdateResourceType sets the "resource_type" field to the value that was provided on create.
func (u *MembershipUpsertOne) UpdateResourceType() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateResourceType()
	})
}

// ClearResourceType clears the value of the "resource_type" field.
func (u *MembershipUpsertOne) ClearResourceType() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearResourceType()
	})
}

// SetResourceID sets the "resource_id" field.
func (u *MembershipUpsertOne) SetResourceID(v uuid.UUID) *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.SetResourceID(v)
	})
}

// UpdateResourceID sets the "resource_id" field to the value that was provided on create.
func (u *MembershipUpsertOne) UpdateResourceID() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateResourceID()
	})
}

// ClearResourceID clears the value of the "resource_id" field.
func (u *MembershipUpsertOne) ClearResourceID() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearResourceID()
	})
}

// SetParentID sets the "parent_id" field.
func (u *MembershipUpsertOne) SetParentID(v uuid.UUID) *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.SetParentID(v)
	})
}

// UpdateParentID sets the "parent_id" field to the value that was provided on create.
func (u *MembershipUpsertOne) UpdateParentID() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateParentID()
	})
}

// ClearParentID clears the value of the "parent_id" field.
func (u *MembershipUpsertOne) ClearParentID() *MembershipUpsertOne {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearParentID()
	})
}

// Exec executes the query.
func (u *MembershipUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for MembershipCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *MembershipUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *MembershipUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("ent: MembershipUpsertOne.ID is not supported by MySQL driver. Use MembershipUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *MembershipUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// MembershipCreateBulk is the builder for creating many Membership entities in bulk.
type MembershipCreateBulk struct {
	config
	err      error
	builders []*MembershipCreate
	conflict []sql.ConflictOption
}

// Save creates the Membership entities in the database.
func (mcb *MembershipCreateBulk) Save(ctx context.Context) ([]*Membership, error) {
	if mcb.err != nil {
		return nil, mcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(mcb.builders))
	nodes := make([]*Membership, len(mcb.builders))
	mutators := make([]Mutator, len(mcb.builders))
	for i := range mcb.builders {
		func(i int, root context.Context) {
			builder := mcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*MembershipMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, mcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = mcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, mcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, mcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (mcb *MembershipCreateBulk) SaveX(ctx context.Context) []*Membership {
	v, err := mcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (mcb *MembershipCreateBulk) Exec(ctx context.Context) error {
	_, err := mcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (mcb *MembershipCreateBulk) ExecX(ctx context.Context) {
	if err := mcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Membership.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.MembershipUpsert) {
//			SetCurrent(v+v).
//		}).
//		Exec(ctx)
func (mcb *MembershipCreateBulk) OnConflict(opts ...sql.ConflictOption) *MembershipUpsertBulk {
	mcb.conflict = opts
	return &MembershipUpsertBulk{
		create: mcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Membership.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (mcb *MembershipCreateBulk) OnConflictColumns(columns ...string) *MembershipUpsertBulk {
	mcb.conflict = append(mcb.conflict, sql.ConflictColumns(columns...))
	return &MembershipUpsertBulk{
		create: mcb,
	}
}

// MembershipUpsertBulk is the builder for "upsert"-ing
// a bulk of Membership nodes.
type MembershipUpsertBulk struct {
	create *MembershipCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.Membership.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(membership.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *MembershipUpsertBulk) UpdateNewValues() *MembershipUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(membership.FieldID)
			}
			if _, exists := b.mutation.CreatedAt(); exists {
				s.SetIgnore(membership.FieldCreatedAt)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Membership.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *MembershipUpsertBulk) Ignore() *MembershipUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *MembershipUpsertBulk) DoNothing() *MembershipUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the MembershipCreateBulk.OnConflict
// documentation for more info.
func (u *MembershipUpsertBulk) Update(set func(*MembershipUpsert)) *MembershipUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&MembershipUpsert{UpdateSet: update})
	}))
	return u
}

// SetCurrent sets the "current" field.
func (u *MembershipUpsertBulk) SetCurrent(v bool) *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.SetCurrent(v)
	})
}

// UpdateCurrent sets the "current" field to the value that was provided on create.
func (u *MembershipUpsertBulk) UpdateCurrent() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateCurrent()
	})
}

// SetUpdatedAt sets the "updated_at" field.
func (u *MembershipUpsertBulk) SetUpdatedAt(v time.Time) *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.SetUpdatedAt(v)
	})
}

// UpdateUpdatedAt sets the "updated_at" field to the value that was provided on create.
func (u *MembershipUpsertBulk) UpdateUpdatedAt() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateUpdatedAt()
	})
}

// SetRole sets the "role" field.
func (u *MembershipUpsertBulk) SetRole(v authz.Role) *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.SetRole(v)
	})
}

// UpdateRole sets the "role" field to the value that was provided on create.
func (u *MembershipUpsertBulk) UpdateRole() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateRole()
	})
}

// SetMembershipType sets the "membership_type" field.
func (u *MembershipUpsertBulk) SetMembershipType(v authz.MembershipType) *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.SetMembershipType(v)
	})
}

// UpdateMembershipType sets the "membership_type" field to the value that was provided on create.
func (u *MembershipUpsertBulk) UpdateMembershipType() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateMembershipType()
	})
}

// ClearMembershipType clears the value of the "membership_type" field.
func (u *MembershipUpsertBulk) ClearMembershipType() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearMembershipType()
	})
}

// SetMemberID sets the "member_id" field.
func (u *MembershipUpsertBulk) SetMemberID(v uuid.UUID) *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.SetMemberID(v)
	})
}

// UpdateMemberID sets the "member_id" field to the value that was provided on create.
func (u *MembershipUpsertBulk) UpdateMemberID() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateMemberID()
	})
}

// ClearMemberID clears the value of the "member_id" field.
func (u *MembershipUpsertBulk) ClearMemberID() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearMemberID()
	})
}

// SetResourceType sets the "resource_type" field.
func (u *MembershipUpsertBulk) SetResourceType(v authz.ResourceType) *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.SetResourceType(v)
	})
}

// UpdateResourceType sets the "resource_type" field to the value that was provided on create.
func (u *MembershipUpsertBulk) UpdateResourceType() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateResourceType()
	})
}

// ClearResourceType clears the value of the "resource_type" field.
func (u *MembershipUpsertBulk) ClearResourceType() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearResourceType()
	})
}

// SetResourceID sets the "resource_id" field.
func (u *MembershipUpsertBulk) SetResourceID(v uuid.UUID) *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.SetResourceID(v)
	})
}

// UpdateResourceID sets the "resource_id" field to the value that was provided on create.
func (u *MembershipUpsertBulk) UpdateResourceID() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateResourceID()
	})
}

// ClearResourceID clears the value of the "resource_id" field.
func (u *MembershipUpsertBulk) ClearResourceID() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearResourceID()
	})
}

// SetParentID sets the "parent_id" field.
func (u *MembershipUpsertBulk) SetParentID(v uuid.UUID) *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.SetParentID(v)
	})
}

// UpdateParentID sets the "parent_id" field to the value that was provided on create.
func (u *MembershipUpsertBulk) UpdateParentID() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.UpdateParentID()
	})
}

// ClearParentID clears the value of the "parent_id" field.
func (u *MembershipUpsertBulk) ClearParentID() *MembershipUpsertBulk {
	return u.Update(func(s *MembershipUpsert) {
		s.ClearParentID()
	})
}

// Exec executes the query.
func (u *MembershipUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the MembershipCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for MembershipCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *MembershipUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
