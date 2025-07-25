//
// Copyright 2024 The Chainloop Authors.
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

package biz

import (
	"context"
	"fmt"
	"time"

	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/auditor/events"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/authz"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/pagination"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
)

type Membership struct {
	ID, OrganizationID   uuid.UUID
	Current              bool
	CreatedAt, UpdatedAt *time.Time
	Org                  *Organization
	User                 *User
	Role                 authz.Role
	// polymorphic membership
	MembershipType authz.MembershipType
	MemberID       uuid.UUID
	ResourceType   authz.ResourceType
	ResourceID     uuid.UUID
	ParentID       *uuid.UUID
}

// ListByOrgOpts are the options to filter memberships of an organization
type ListByOrgOpts struct {
	// MembershipID the ID of the membership to filter by
	MembershipID *uuid.UUID
	// Name the name of the user to filter memberships by
	Name *string
	// Email the email of the user to filter memberships by
	Email *string
	// Role the role of the user to filter memberships by
	Role *authz.Role
}

type MembershipRepo interface {
	FindByUser(ctx context.Context, userID uuid.UUID) ([]*Membership, error)
	FindByOrgIDAndUserEmail(ctx context.Context, orgID uuid.UUID, userEmail string) (*Membership, error)
	FindByUserAndResourceID(ctx context.Context, userID, resourceID uuid.UUID) (*Membership, error)
	FindByOrg(ctx context.Context, orgID uuid.UUID, opts *ListByOrgOpts, paginationOpts *pagination.OffsetPaginationOpts) ([]*Membership, int, error)
	FindByIDInUser(ctx context.Context, userID, ID uuid.UUID) (*Membership, error)
	FindByIDInOrg(ctx context.Context, orgID, ID uuid.UUID) (*Membership, error)
	FindByOrgAndUser(ctx context.Context, orgID, userID uuid.UUID) (*Membership, error)
	FindByOrgNameAndUser(ctx context.Context, orgName string, userID uuid.UUID) (*Membership, error)
	SetCurrent(ctx context.Context, ID uuid.UUID) (*Membership, error)
	SetRole(ctx context.Context, ID uuid.UUID, role authz.Role) (*Membership, error)
	Create(ctx context.Context, orgID, userID uuid.UUID, current bool, role authz.Role) (*Membership, error)
	Delete(ctx context.Context, ID uuid.UUID) error

	// RBAC methods

	ListAllByUser(ctx context.Context, userID uuid.UUID) ([]*Membership, error)
	// ListGroupMembershipsByUser returns all memberships of the users inherited from groups
	ListGroupMembershipsByUser(ctx context.Context, userID uuid.UUID) ([]*Membership, error)
	ListAllByResource(ctx context.Context, rt authz.ResourceType, id uuid.UUID) ([]*Membership, error)
	AddResourceRole(ctx context.Context, orgID uuid.UUID, resourceType authz.ResourceType, resID uuid.UUID, mType authz.MembershipType, memberID uuid.UUID, role authz.Role, parentID *uuid.UUID) error
}

type MembershipsRBAC interface {
	ListAllMembershipsForUser(ctx context.Context, userID uuid.UUID) ([]*Membership, error)
}

type MembershipUseCase struct {
	logger *log.Helper
	// Repositories
	repo     MembershipRepo
	userRepo UserRepo
	// Use Cases
	orgUseCase *OrganizationUseCase
	auditor    *AuditorUseCase
}

func NewMembershipUseCase(repo MembershipRepo, orgUC *OrganizationUseCase, auditor *AuditorUseCase, userRepo UserRepo, logger log.Logger) *MembershipUseCase {
	return &MembershipUseCase{repo: repo, orgUseCase: orgUC, logger: log.NewHelper(logger), userRepo: userRepo, auditor: auditor}
}

// LeaveAndDeleteOrg deletes a membership (and the org i) from the database associated with the current user
// and the associated org if the user is the only member
func (uc *MembershipUseCase) LeaveAndDeleteOrg(ctx context.Context, userID, membershipID string) error {
	membershipUUID, err := uuid.Parse(membershipID)
	if err != nil {
		return NewErrInvalidUUID(err)
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return NewErrInvalidUUID(err)
	}

	// Check that the provided membershipID in fact belongs to a membership from the user
	m, err := uc.repo.FindByIDInUser(ctx, userUUID, membershipUUID)
	if err != nil {
		return fmt.Errorf("failed to find membership: %w", err)
	} else if m == nil {
		return NewErrNotFound("membership")
	}

	uc.logger.Infow("msg", "Deleting membership", "user_id", userID, "membership_id", m.ID.String())
	if err := uc.repo.Delete(ctx, membershipUUID); err != nil {
		return fmt.Errorf("failed to delete membership: %w", err)
	}

	uc.auditor.Dispatch(ctx, &events.OrgUserLeft{
		OrgBase: &events.OrgBase{
			OrgID:   &m.OrganizationID,
			OrgName: m.Org.Name,
		},
	}, &m.OrganizationID)

	// Check number of members in the org
	// If it's the only one, delete the org
	_, membershipCount, err := uc.repo.FindByOrg(ctx, m.OrganizationID, &ListByOrgOpts{}, pagination.NewDefaultOffsetPaginationOpts())
	if err != nil {
		return fmt.Errorf("failed to find memberships in org: %w", err)
	}

	if membershipCount == 0 {
		// Delete the org
		uc.logger.Infow("msg", "Deleting organization", "organization_id", m.OrganizationID.String())
		if err := uc.orgUseCase.Delete(ctx, m.OrganizationID.String()); err != nil {
			return fmt.Errorf("failed to delete org: %w", err)
		}
	}

	return nil
}

// DeleteOther just deletes a membership from the database
// but ensures that the user is not deleting itself from the org
func (uc *MembershipUseCase) DeleteOther(ctx context.Context, orgID, userID, membershipID string) error {
	membershipUUID, err := uuid.Parse(membershipID)
	if err != nil {
		return NewErrInvalidUUID(err)
	}

	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return NewErrInvalidUUID(err)
	}

	m, err := uc.repo.FindByIDInOrg(ctx, orgUUID, membershipUUID)
	if err != nil {
		return fmt.Errorf("failed to find membership: %w", err)
	} else if m == nil {
		return NewErrNotFound("membership")
	}

	if m.User.ID == userID {
		return NewErrValidationStr("cannot delete yourself from the org")
	}

	uc.logger.Infow("msg", "Deleting membership", "org_id", orgID, "membership_id", m.ID.String())

	// Delete the main membership - this will also remove the user from all groups in the org
	// and clean up associated resource memberships in the data layer
	if err := uc.repo.Delete(ctx, membershipUUID); err != nil {
		return fmt.Errorf("failed to delete membership: %w", err)
	}

	return nil
}

func (uc *MembershipUseCase) UpdateRole(ctx context.Context, orgID, userID, membershipID string, role authz.Role) (*Membership, error) {
	// If it has ben overrode by the user, validate it
	if role == "" {
		return nil, NewErrValidationStr("role is required")
	}

	membershipUUID, err := uuid.Parse(membershipID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	m, err := uc.repo.FindByIDInOrg(ctx, orgUUID, membershipUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to find membership: %w", err)
	}

	if m == nil {
		return nil, NewErrNotFound("membership")
	}

	if m.User.ID == userID {
		return nil, NewErrValidationStr("cannot update yourself")
	}

	userUUID, err := uuid.Parse(m.User.ID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	user, err := uc.userRepo.FindByID(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	updatedMembership, err := uc.repo.SetRole(ctx, membershipUUID, role)
	if err != nil {
		return nil, fmt.Errorf("failed to update membership role: %w", err)
	}

	uc.auditor.Dispatch(ctx, &events.UserRoleChanged{
		UserBase: &events.UserBase{
			UserID: &userUUID,
			Email:  user.Email,
		},
		OldRole: string(m.Role),
		NewRole: string(role),
	}, &m.OrganizationID)

	return updatedMembership, nil
}

type membershipCreateOpts struct {
	current bool
	role    authz.Role
}

type MembershipCreateOpt func(*membershipCreateOpts)

func WithCurrentMembership() MembershipCreateOpt {
	return func(o *membershipCreateOpts) {
		o.current = true
	}
}

func WithMembershipRole(r authz.Role) MembershipCreateOpt {
	return func(o *membershipCreateOpts) {
		o.role = r
	}
}

func (uc *MembershipUseCase) Create(ctx context.Context, orgID, userID string, opts ...MembershipCreateOpt) (*Membership, error) {
	cp := &membershipCreateOpts{
		// Default role
		role: authz.RoleViewer,
	}

	for _, o := range opts {
		o(cp)
	}

	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	m, err := uc.repo.Create(ctx, orgUUID, userUUID, cp.current, cp.role)
	if err != nil {
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}

	if !cp.current {
		return m, nil
	}

	// Set the current membership again to make sure we uncheck the previous ones
	return uc.repo.SetCurrent(ctx, m.ID)
}

func (uc *MembershipUseCase) ByUser(ctx context.Context, userID string) ([]*Membership, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	return uc.repo.FindByUser(ctx, userUUID)
}

func (uc *MembershipUseCase) ByOrg(ctx context.Context, orgID string, opts *ListByOrgOpts, paginationOpts *pagination.OffsetPaginationOpts) ([]*Membership, int, error) {
	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return nil, 0, NewErrInvalidUUID(err)
	}

	if opts == nil {
		opts = &ListByOrgOpts{}
	}

	pgOpts := paginationOpts
	if pgOpts == nil {
		pgOpts = pagination.NewDefaultOffsetPaginationOpts()
	}

	return uc.repo.FindByOrg(ctx, orgUUID, opts, pgOpts)
}

// SetCurrent sets the current membership for the user
// and unsets the previous one
func (uc *MembershipUseCase) SetCurrent(ctx context.Context, userID, membershipID string) (*Membership, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	mUUID, err := uuid.Parse(membershipID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	// Check that the provided membershipID in fact refers to one from this user
	if m, err := uc.repo.FindByIDInUser(ctx, userUUID, mUUID); err != nil {
		return nil, err
	} else if m == nil {
		return nil, NewErrNotFound("membership")
	}

	return uc.repo.SetCurrent(ctx, mUUID)
}

func (uc *MembershipUseCase) FindByOrgAndUser(ctx context.Context, orgID, userID string) (*Membership, error) {
	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	m, err := uc.repo.FindByOrgAndUser(ctx, orgUUID, userUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to find membership: %w", err)
	} else if m == nil {
		return nil, NewErrNotFound("membership")
	}

	return m, nil
}

func (uc *MembershipUseCase) FindByOrgNameAndUser(ctx context.Context, orgName, userID string) (*Membership, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, NewErrInvalidUUID(err)
	}

	m, err := uc.repo.FindByOrgNameAndUser(ctx, orgName, userUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to find membership: %w", err)
	} else if m == nil {
		return nil, NewErrNotFound("membership")
	}

	return m, nil
}

// RBAC methods

// ListAllMembershipsForUser retrieves all memberships for a user, including both direct memberships and those inherited from groups
func (uc *MembershipUseCase) ListAllMembershipsForUser(ctx context.Context, userID uuid.UUID) ([]*Membership, error) {
	// First retrieve all memberships directly associated with the user
	userMemberships, err := uc.repo.ListAllByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships for user: %w", err)
	}

	// Then retrieve all group memberships for the user
	groupMemberships, err := uc.repo.ListGroupMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list group memberships for user: %w", err)
	}

	return append(userMemberships, groupMemberships...), nil
}

// SetProjectOwner sets the project owner (admin role). It skips the operation if an owner exists already
func (uc *MembershipUseCase) SetProjectOwner(ctx context.Context, orgID, projectID, userID uuid.UUID) error {
	mm, err := uc.repo.ListAllByResource(ctx, authz.ResourceTypeProject, projectID)
	if err != nil {
		return fmt.Errorf("failed to find membership: %w", err)
	}

	for _, m := range mm {
		if m.Role == authz.RoleProjectAdmin {
			// Found one already
			return nil
		}
	}

	if err = uc.repo.AddResourceRole(ctx, orgID, authz.ResourceTypeProject, projectID, authz.MembershipTypeUser, userID, authz.RoleProjectAdmin, nil); err != nil {
		return fmt.Errorf("failed to set project owner: %w", err)
	}

	return nil
}

func (uc *MembershipUseCase) GetOrgsAndRBACInfoForUser(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, map[uuid.UUID][]uuid.UUID, error) {
	// Load ALL memberships for the given user
	memberships, err := uc.ListAllMembershipsForUser(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list memberships: %w", err)
	}

	userOrgs := make([]uuid.UUID, 0)
	// This map holds the list of project IDs by org with RBAC active (user is org "member")
	projectIDs := make(map[uuid.UUID][]uuid.UUID)
	for _, m := range memberships {
		if m.ResourceType == authz.ResourceTypeOrganization {
			userOrgs = append(userOrgs, m.ResourceID)
			// If the role in the org is member, we must enable RBAC for projects.
			if m.Role.RBACEnabled() {
				// get the list of projects in org, and match it with the memberships to build a filter.
				// note that appending an empty slice to a nil slice doesn't change it (it's still nil)
				projectIDs[m.ResourceID] = getProjectsWithMembershipInOrg(m.ResourceID, memberships)
			}
		}
	}

	return userOrgs, projectIDs, nil
}
