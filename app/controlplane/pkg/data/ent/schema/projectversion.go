//
// Copyright 2024-2025 The Chainloop Authors.
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
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	"github.com/google/uuid"
)

// ProjectVersion holds the schema definition for the ProjectVersion entity.
type ProjectVersion struct {
	ent.Schema
}

// Fields of the Version.
func (ProjectVersion) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Unique(),
		// empty version means no defined version
		field.String("version").Default("").Validate(func(s string) error {
			if s == "" {
				return nil
			}
			return biz.ValidateVersion(s)
		}),
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
		field.Time("deleted_at").Optional(),
		field.UUID("project_id", uuid.UUID{}),
		field.Bool("prerelease").Default(true),
		field.Int("workflow_run_count").Default(0),
		// When the version was released
		field.Time("released_at").Optional(),
		field.Bool("latest").Default(false).Comment("Whether this is the latest version of the project"),
	}
}

// Edges of the Version.
func (ProjectVersion) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("project", Project.Type).Field("project_id").Ref("versions").Unique().Required(),
		edge.To("runs", WorkflowRun.Type),
	}
}

func (ProjectVersion) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("version", "project_id").Unique().Annotations(
			entsql.IndexWhere("deleted_at IS NULL"),
		),
	}
}
