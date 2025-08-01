//
// Copyright 2023 The Chainloop Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/authz"
	"github.com/google/uuid"
)

// Membership maps users belonging to organizations
type Membership struct {
	ent.Schema
}

func (Membership) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Unique(),
		field.Bool("current").Default(false),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Annotations(&entsql.Annotation{
				Default: "CURRENT_TIMESTAMP",
			}),
		field.Time("updated_at").
			Default(time.Now).
			Annotations(&entsql.Annotation{
				Default: "CURRENT_TIMESTAMP",
			}),
		// rbac role in the organization
		field.Enum("role").GoType(authz.Role("")),

		// polymorphic membership for RBAC
		field.Enum("membership_type").GoType(authz.MembershipType("")).Optional(),
		field.UUID("member_id", uuid.UUID{}).Optional(),

		field.Enum("resource_type").GoType(authz.ResourceType("")).Optional(),
		field.UUID("resource_id", uuid.UUID{}).Optional(),

		// Optional role inheritance
		// foreign key points to the parent membership ID
		field.UUID("parent_id", uuid.UUID{}).Optional().Nillable(),
	}
}

func (Membership) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).Ref("memberships").Unique(),
		edge.From("user", User.Type).Ref("memberships").Unique(),

		// inheritance
		edge.To("children", Membership.Type).Annotations(entsql.Annotation{OnDelete: entsql.Cascade}).From("parent").Field("parent_id").Unique(),
	}
}

func (Membership) Indexes() []ent.Index {
	return []ent.Index{
		index.Edges("organization", "user"),
		// only one inherited role
		index.Fields("membership_type", "member_id", "resource_type", "resource_id", "parent_id").Unique().Annotations(
			entsql.IndexWhere("parent_id IS NOT NULL"),
		),
		// only one explicit role
		index.Fields("membership_type", "member_id", "resource_type", "resource_id").Unique().Annotations(
			entsql.IndexWhere("parent_id IS NULL"),
		),
	}
}
