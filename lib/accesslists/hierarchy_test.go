/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package accesslists

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/accesslist"
	"github.com/gravitational/teleport/api/types/header"
)

// Mock implementation of AccessListMembersGetter.
type mockMembersGetter struct {
	members map[string][]*accesslist.AccessListMember
}

func (m *mockMembersGetter) ListAccessListMembers(ctx context.Context, accessListName string, pageSize int, pageToken string) ([]*accesslist.AccessListMember, string, error) {
	members, exists := m.members[accessListName]
	if !exists {
		return nil, "", nil
	}
	return members, "", nil
}

type mockLocksGetter struct {
	targets map[string][]types.Lock
}

func (m *mockLocksGetter) GetLock(ctx context.Context, name string) (types.Lock, error) {
	panic("not implemented")
}

func (m *mockLocksGetter) GetLocks(ctx context.Context, inForceOnly bool, targets ...types.LockTarget) ([]types.Lock, error) {
	var locks []types.Lock
	for _, target := range targets {
		locks = append(locks, m.targets[target.User]...)
	}
	return locks, nil
}

const (
	ownerUser  = "ownerUser"
	ownerUser2 = "ownerUser2"
	member1    = "member1"
	member2    = "member2"
)

func TestNewAccessListHierarchy(t *testing.T) {
	clock := clockwork.NewFakeClock()
	ctx := context.Background()

	acl1 := newAccessList(t, "1", clock)
	acl2 := newAccessList(t, "2", clock)
	acl3 := newAccessList(t, "3", clock)
	acl4 := newAccessList(t, "4", clock)
	acl5 := newAccessList(t, "5", clock)

	// acl1 -> acl2 -> acl3
	acl1m1 := newAccessListMember(t, acl1.GetName(), acl2.GetName(), accesslist.MembershipKindList, clock)
	acl2m1 := newAccessListMember(t, acl2.GetName(), acl3.GetName(), accesslist.MembershipKindList, clock)

	// acl4 -> acl1,acl2
	acl4m1 := newAccessListMember(t, acl4.GetName(), acl1.GetName(), accesslist.MembershipKindList, clock)
	acl4m2 := newAccessListMember(t, acl4.GetName(), acl2.GetName(), accesslist.MembershipKindList, clock)

	acl5.Spec.Owners = append(acl5.Spec.Owners, accesslist.Owner{
		Name:           acl4.GetName(),
		Description:    "asdf",
		MembershipKind: accesslist.MembershipKindList,
	})

	membersGetter := &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{
			acl1.GetName(): {acl1m1},
			acl2.GetName(): {acl2m1},
			acl3.GetName(): {},
			acl4.GetName(): {acl4m1, acl4m2},
			acl5.GetName(): {},
		},
	}

	// Hierarchy should be built successfully.
	_, err := NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{acl1, acl2, acl3, acl4, acl5},
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	// When no lists are provided, should still build successfully (e.g., when no access lists yet).
	_, err = NewHierarchy(ctx, HierarchyConfig{
		AccessLists: nil,
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)
	_, err = NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{},
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	// When no Clock is provided, should create new RealClock internally.
	_, err = NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{acl1, acl2, acl3, acl4, acl5},
		Members:     membersGetter,
		Locks:       nil,
		Clock:       nil,
	})
	require.NoError(t, err)

	// When no MembersGetter is provided, should return BadParam
	_, err = NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{},
		Members:     nil,
		Locks:       nil,
		Clock:       clock,
	})
	require.ErrorIs(t, err, trace.BadParameter("MembersGetter is required"))
}

func TestAccessListHierarchyDepthCheck(t *testing.T) {
	clock := clockwork.NewFakeClock()
	ctx := context.Background()

	numAcls := accesslist.MaxAllowedDepth + 2 // Extra 2 to test exceeding the max depth

	acls := make([]*accesslist.AccessList, numAcls)
	for i := 0; i < numAcls; i++ {
		acls[i] = newAccessList(t, fmt.Sprintf("acl%d", i+1), clock)
	}

	membersGetter := &mockMembersGetter{
		members: make(map[string][]*accesslist.AccessListMember),
	}

	// Create members up to MaxAllowedDepth
	for i := 0; i < accesslist.MaxAllowedDepth; i++ {
		member := newAccessListMember(t, acls[i].GetName(), acls[i+1].GetName(), accesslist.MembershipKindList, clock)
		membersGetter.members[acls[i].GetName()] = []*accesslist.AccessListMember{member}
	}
	// Set remaining Access Lists' members to empty slices
	for i := accesslist.MaxAllowedDepth; i < numAcls; i++ {
		membersGetter.members[acls[i].GetName()] = []*accesslist.AccessListMember{}
	}

	// Should create hierarchy successfully with depth equal to MaxAllowedDepth
	hierarchy, err := NewHierarchy(ctx, HierarchyConfig{
		AccessLists: acls[:accesslist.MaxAllowedDepth+2],
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	// Now, attempt to add a member that increases the depth beyond MaxAllowedDepth
	extraMember := newAccessListMember(
		t,
		acls[accesslist.MaxAllowedDepth].GetName(),
		acls[accesslist.MaxAllowedDepth+1].GetName(),
		accesslist.MembershipKindList,
		clock,
	)

	// Validate adding this member should fail due to exceeding max depth
	err = hierarchy.ValidateAccessListMember(acls[accesslist.MaxAllowedDepth].GetName(), extraMember)
	require.Error(t, err)
	require.ErrorIs(t, err, trace.BadParameter("Access List '%s' can't be added as a Member of '%s' because it would exceed the maximum nesting depth of %d", acls[accesslist.MaxAllowedDepth+1].Spec.Title, acls[accesslist.MaxAllowedDepth].Spec.Title, accesslist.MaxAllowedDepth))

	// Now, add this member to the membersGetter and attempt to create the hierarchy again, which should fail
	membersGetter.members[acls[accesslist.MaxAllowedDepth].GetName()] = []*accesslist.AccessListMember{extraMember}

	// Attempt to create the hierarchy with the new member
	_, err = NewHierarchy(ctx, HierarchyConfig{
		AccessLists: acls,
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, trace.BadParameter("Access List '%s' can't be added as a Member of '%s' because it would exceed the maximum nesting depth of %d", acls[accesslist.MaxAllowedDepth+1].Spec.Title, acls[accesslist.MaxAllowedDepth].Spec.Title, accesslist.MaxAllowedDepth))
}

func TestAccessListValidateWithMembers(t *testing.T) {
	clock := clockwork.NewFakeClock()
	ctx := context.Background()

	// We're creating a hierarchy with a depth of 10, and then trying to add it as a Member of a 'root' Access List. This should fail.
	rootAcl := newAccessList(t, "root", clock)
	nestedAcls := make([]*accesslist.AccessList, 0, accesslist.MaxAllowedDepth)
	for i := 0; i < accesslist.MaxAllowedDepth+1; i++ {
		acl := newAccessList(t, fmt.Sprintf("acl-%d", i), clock)
		nestedAcls = append(nestedAcls, acl)
	}
	rootAclMember := newAccessListMember(t, rootAcl.GetName(), nestedAcls[0].GetName(), accesslist.MembershipKindList, clock)
	members := make([]*accesslist.AccessListMember, 0, accesslist.MaxAllowedDepth-1)
	for i := 0; i < accesslist.MaxAllowedDepth; i++ {
		member := newAccessListMember(t, nestedAcls[i].GetName(), nestedAcls[i+1].GetName(), accesslist.MembershipKindList, clock)
		members = append(members, member)
	}

	membersGetter := &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{
			rootAcl.GetName(): {},
		},
	}
	for i := 0; i < accesslist.MaxAllowedDepth; i++ {
		membersGetter.members[nestedAcls[i].GetName()] = []*accesslist.AccessListMember{members[i]}
	}

	// Should create successfully, as acl-0 -> acl-10 is a valid hierarchy of depth 10.
	hierarchy, err := NewHierarchy(ctx, HierarchyConfig{
		AccessLists: append([]*accesslist.AccessList{rootAcl}, nestedAcls...),
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	// Calling `ValidateAccessListWithMembers`, with `rootAclm1`, should fail, as it would exceed the maximum nesting depth.
	err = hierarchy.ValidateAccessListWithMembers(rootAcl, []*accesslist.AccessListMember{rootAclMember})
	require.Error(t, err)
	require.ErrorIs(t, err, trace.BadParameter("Access List '%s' can't be added as a Member of '%s' because it would exceed the maximum nesting depth of %d", nestedAcls[0].Spec.Title, rootAcl.Spec.Title, accesslist.MaxAllowedDepth))

	const Length = accesslist.MaxAllowedDepth/2 + 1

	// Next, we're creating two separate hierarchies, each with a depth of `MaxAllowedDepth/2`. When testing the validation, we'll try to connect the two hierarchies, which should fail.
	nestedAcls1 := make([]*accesslist.AccessList, 0, Length)
	for i := 0; i <= Length; i++ {
		acl := newAccessList(t, fmt.Sprintf("acl1-%d", i), clock)
		nestedAcls1 = append(nestedAcls1, acl)
	}

	// Create the second hierarchy.
	nestedAcls2 := make([]*accesslist.AccessList, 0, Length)
	for i := 0; i <= Length; i++ {
		acl := newAccessList(t, fmt.Sprintf("acl2-%d", i), clock)
		nestedAcls2 = append(nestedAcls2, acl)
	}

	membersGetter = &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{},
	}

	// Create the members for the first hierarchy.
	for i := 0; i < Length; i++ {
		member := newAccessListMember(t, nestedAcls1[i].GetName(), nestedAcls1[i+1].GetName(), accesslist.MembershipKindList, clock)
		membersGetter.members[nestedAcls1[i].GetName()] = []*accesslist.AccessListMember{member}
	}

	// Create the members for the second hierarchy.
	for i := 0; i < Length; i++ {
		member := newAccessListMember(t, nestedAcls2[i].GetName(), nestedAcls2[i+1].GetName(), accesslist.MembershipKindList, clock)
		membersGetter.members[nestedAcls2[i].GetName()] = []*accesslist.AccessListMember{member}
	}

	// Should create successfully, as both hierarchies are valid.
	hierarchy, err = NewHierarchy(ctx, HierarchyConfig{
		AccessLists: append(nestedAcls1, nestedAcls2...),
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	nestedAcls1Last := nestedAcls1[len(nestedAcls1)-1]

	// Now, we'll try to connect the two hierarchies, which should fail.
	err = hierarchy.ValidateAccessListWithMembers(nestedAcls1Last, []*accesslist.AccessListMember{newAccessListMember(t, nestedAcls1Last.GetName(), nestedAcls2[0].GetName(), accesslist.MembershipKindList, clock)})
	require.Error(t, err)
	require.ErrorIs(t, err, trace.BadParameter("Access List '%s' can't be added as a Member of '%s' because it would exceed the maximum nesting depth of %d", nestedAcls2[0].Spec.Title, nestedAcls1[len(nestedAcls1)-1].Spec.Title, accesslist.MaxAllowedDepth))
}

func TestAccessListHierarchyCircularRefsCheck(t *testing.T) {
	clock := clockwork.NewFakeClock()
	ctx := context.Background()

	acl1 := newAccessList(t, "1", clock)
	acl2 := newAccessList(t, "2", clock)
	acl3 := newAccessList(t, "3", clock)

	// acl1 -> acl2 -> acl3
	acl1m1 := newAccessListMember(t, acl1.GetName(), acl2.GetName(), accesslist.MembershipKindList, clock)
	acl2m1 := newAccessListMember(t, acl2.GetName(), acl3.GetName(), accesslist.MembershipKindList, clock)

	// acl3 -> acl1
	acl3m1 := newAccessListMember(t, acl3.GetName(), acl1.GetName(), accesslist.MembershipKindList, clock)

	membersGetter := &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{
			acl1.GetName(): {acl1m1},
			acl2.GetName(): {acl2m1},
			acl3.GetName(): {},
		},
	}

	// Hierarchy should be built successfully.
	hierarchy, err := NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{acl1, acl2, acl3},
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	// Circular references should not be allowed.
	err = hierarchy.ValidateAccessListMember(acl3.GetName(), acl3m1)
	require.Error(t, err)
	require.ErrorIs(t, err, trace.BadParameter("Access List '%s' can't be added as a Member of '%s' because '%s' is already included as a Member or Owner in '%s'", acl1.Spec.Title, acl3.Spec.Title, acl3.Spec.Title, acl1.Spec.Title))

	membersGetter.members[acl3.GetName()] = []*accesslist.AccessListMember{acl3m1}

	// After 'creating' the member that links acl3 to acl1, validation should fail due to circular reference.
	_, err = NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{acl1, acl2, acl3},
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, trace.BadParameter("Access List '%s' can't be added as a Member of '%s' because '%s' is already included as a Member or Owner in '%s'", acl1.Spec.Title, acl3.Spec.Title, acl3.Spec.Title, acl1.Spec.Title))

	// Circular references with Ownership should also be disallowed.
	acl4 := newAccessList(t, "4", clock)
	acl5 := newAccessList(t, "5", clock)

	// acl4 includes acl5 as a Member
	acl4m1 := newAccessListMember(t, acl4.GetName(), acl5.GetName(), accesslist.MembershipKindList, clock)

	// acl5 includes acl4 as an Owner.
	acl5.Spec.Owners = append(acl5.Spec.Owners, accesslist.Owner{
		Name:           acl4.GetName(),
		Description:    "asdf",
		MembershipKind: accesslist.MembershipKindList,
	})

	membersGetter = &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{
			acl4.GetName(): {acl4m1},
			acl5.GetName(): {},
		},
	}

	_, err = NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{acl4, acl5},
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, trace.BadParameter("Access List '%s' can't be added as an Owner of '%s' because '%s' is already included as a Member or Owner in '%s'", acl4.Spec.Title, acl5.Spec.Title, acl5.Spec.Title, acl4.Spec.Title))
}

func TestAccessListHierarchyIsOwner(t *testing.T) {
	clock := clockwork.NewFakeClock()
	ctx := context.Background()

	acl1 := newAccessList(t, "1", clock)
	acl2 := newAccessList(t, "2", clock)
	acl3 := newAccessList(t, "3", clock)
	acl4 := newAccessList(t, "4", clock)

	// acl1 -> acl2 -> acl3 as members
	acl1m1 := newAccessListMember(t, acl1.GetName(), acl2.GetName(), accesslist.MembershipKindList, clock)
	acl1m2 := newAccessListMember(t, acl1.GetName(), member1, accesslist.MembershipKindUser, clock)
	acl2m1 := newAccessListMember(t, acl2.GetName(), acl3.GetName(), accesslist.MembershipKindList, clock)
	acl4m1 := newAccessListMember(t, acl4.GetName(), member2, accesslist.MembershipKindUser, clock)

	// acl4 -> acl1 as owner
	acl4.Spec.Owners = append(acl4.Spec.Owners, accesslist.Owner{
		Name:           acl1.GetName(),
		Description:    "asdf",
		MembershipKind: accesslist.MembershipKindList,
	})

	membersGetter := &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{
			acl1.GetName(): {acl1m1, acl1m2},
			acl2.GetName(): {acl2m1},
			acl3.GetName(): {},
			acl4.GetName(): {acl4m1},
		},
	}

	// Hierarchy should be built successfully.
	hierarchy, err := NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{acl1, acl2, acl3, acl4},
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	// User which does not meet acl1's Membership requirements.
	stubUserNoRequires, err := types.NewUser(member1)
	require.NoError(t, err)

	ownershipType, err := hierarchy.IsAccessListOwner(context.Background(), stubUserNoRequires, acl4.GetName())
	require.Error(t, err)
	require.ErrorIs(t, err, trace.AccessDenied("User '%s' does not meet the membership requirements for Access List '%s'", member1, acl1.Spec.Title))
	// Should not have inherited ownership due to missing OwnershipRequires.
	require.Equal(t, MembershipOrOwnershipTypeNone, ownershipType)

	// User which only meets acl1's Membership requirements.
	stubUserMeetsMemberRequires, err := types.NewUser(member1)
	require.NoError(t, err)
	stubUserMeetsMemberRequires.SetTraits(map[string][]string{
		"mtrait1": {"mvalue1", "mvalue2"},
		"mtrait2": {"mvalue3", "mvalue4"},
	})
	stubUserMeetsMemberRequires.SetRoles([]string{"mrole1", "mrole2"})

	ownershipType, err = hierarchy.IsAccessListOwner(context.Background(), stubUserMeetsMemberRequires, acl4.GetName())
	require.Error(t, err)
	require.ErrorIs(t, err, trace.AccessDenied("User '%s' does not meet the ownership requirements for Access List '%s'", member1, acl4.Spec.Title))
	require.Equal(t, MembershipOrOwnershipTypeNone, ownershipType)

	// User which meets acl1's Membership and acl1's Ownership requirements.
	stubUserMeetsAllRequires, err := types.NewUser(member1)
	require.NoError(t, err)
	stubUserMeetsAllRequires.SetTraits(map[string][]string{
		"mtrait1": {"mvalue1", "mvalue2"},
		"mtrait2": {"mvalue3", "mvalue4"},
		"otrait1": {"ovalue1", "ovalue2"},
		"otrait2": {"ovalue3", "ovalue4"},
	})
	stubUserMeetsAllRequires.SetRoles([]string{"mrole1", "mrole2", "orole1", "orole2"})

	ownershipType, err = hierarchy.IsAccessListOwner(context.Background(), stubUserMeetsAllRequires, acl4.GetName())
	require.NoError(t, err)
	// Should have inherited ownership from acl1's inclusion in acl4's Owners.
	require.Equal(t, MembershipOrOwnershipTypeInherited, ownershipType)

	stubUserMeetsAllRequires.SetName(member2)
	ownershipType, err = hierarchy.IsAccessListOwner(context.Background(), stubUserMeetsAllRequires, acl4.GetName())
	require.NoError(t, err)
	// Should not have ownership.
	require.Equal(t, MembershipOrOwnershipTypeNone, ownershipType)
}

func TestAccessListIsMember(t *testing.T) {
	clock := clockwork.NewFakeClock()
	ctx := context.Background()

	acl1 := newAccessList(t, "1", clock)
	acl1m1 := newAccessListMember(t, acl1.GetName(), member1, accesslist.MembershipKindUser, clock)

	locksGetter := &mockLocksGetter{
		targets: map[string][]types.Lock{},
	}
	membersGetter := &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{
			acl1.GetName(): {acl1m1},
		},
	}

	hierarchy, err := NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{acl1},
		Members:     membersGetter,
		Locks:       locksGetter,
		Clock:       clock,
	})
	require.NoError(t, err)

	stubMember1, err := types.NewUser(member1)
	require.NoError(t, err)
	stubMember1.SetTraits(map[string][]string{
		"mtrait1": {"mvalue1", "mvalue2"},
		"mtrait2": {"mvalue3", "mvalue4"},
	})
	stubMember1.SetRoles([]string{"mrole1", "mrole2"})

	membershipType, err := hierarchy.IsAccessListMember(context.Background(), stubMember1, acl1.GetName())
	require.NoError(t, err)
	require.Equal(t, MembershipOrOwnershipTypeExplicit, membershipType)

	// When user is Locked, should not be considered a Member.
	lock, err := types.NewLock("user-lock", types.LockSpecV2{
		Target: types.LockTarget{
			User: member1,
		},
	})
	require.NoError(t, err)
	locksGetter.targets[member1] = []types.Lock{lock}

	membershipType, err = hierarchy.IsAccessListMember(context.Background(), stubMember1, acl1.GetName())
	require.ErrorIs(t, err, trace.AccessDenied("User '%s' is currently locked", member1))
	require.Equal(t, MembershipOrOwnershipTypeNone, membershipType)
}

func TestGetOwners(t *testing.T) {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	// Create Access Lists
	acl1 := newAccessList(t, "1", clock)
	acl2 := newAccessList(t, "2", clock)
	acl3 := newAccessList(t, "3", clock)

	// Set up owners
	// acl1 is owned by user "ownerA" and access list acl2
	acl1.Spec.Owners = []accesslist.Owner{
		{
			Name:           "ownerA",
			MembershipKind: accesslist.MembershipKindUser,
		},
		{
			Name:           "2",
			MembershipKind: accesslist.MembershipKindList,
		},
	}

	// acl2 is owned by user "ownerB" and access list aclC
	acl2.Spec.Owners = []accesslist.Owner{
		{
			Name:           "ownerB",
			MembershipKind: accesslist.MembershipKindUser,
		},
		{
			Name:           "3",
			MembershipKind: accesslist.MembershipKindList,
		},
	}

	// acl3 is owned by user "ownerC"
	acl3.Spec.Owners = []accesslist.Owner{
		{
			Name:           "ownerC",
			MembershipKind: accesslist.MembershipKindUser,
		},
	}

	// Set up members for owner lists
	// aclB has member "memberB"
	acl2m1 := newAccessListMember(t, acl2.GetName(), "memberB", accesslist.MembershipKindUser, clock)
	// aclC has member "memberC"
	acl3m1 := newAccessListMember(t, acl3.GetName(), "memberC", accesslist.MembershipKindUser, clock)

	// Prepare access lists and members
	accessLists := []*accesslist.AccessList{acl1, acl2, acl3}
	membersGetter := &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{
			acl2.GetName(): {acl2m1},
			acl3.GetName(): {acl3m1},
		},
	}

	// Create Hierarchy
	hierarchy, err := NewHierarchy(ctx, HierarchyConfig{
		AccessLists: accessLists,
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	// Test GetOwners for acl1
	owners, err := hierarchy.GetOwners(acl1.GetName())
	require.NoError(t, err)

	// Expected owners:
	// - Direct owner: "ownerA"
	// - Inherited owners via acl2 (since acl2 is an owner of acl1):
	//   - Members of acl2: "memberB"
	// Note: Owners of acl2 ("ownerB") and members/owners of acl3 are not inherited by acl1

	expectedOwners := map[string]bool{
		"ownerA":  true, // Direct owner of acl1
		"memberB": true, // Member of acl2 (owner list of acl1)
	}

	actualOwners := make(map[string]bool)
	for _, owner := range owners {
		actualOwners[owner.Name] = true
	}

	require.Equal(t, expectedOwners, actualOwners, "Owners do not match expected owners")

	// Test GetOwners for acl2
	owners, err = hierarchy.GetOwners(acl2.GetName())
	require.NoError(t, err)

	// Expected owners:
	// - Direct owner: "ownerB"
	// - Inherited owners via acl3 (since acl3 is an owner of acl2):
	//   - Members of acl3: "memberC"

	expectedOwners = map[string]bool{
		"ownerB":  true, // Direct owner of acl2
		"memberC": true, // Member of acl3 (owner list of acl2)
	}

	actualOwners = make(map[string]bool)
	for _, owner := range owners {
		actualOwners[owner.Name] = true
	}

	require.Equal(t, expectedOwners, actualOwners, "Owners do not match expected owners")
}

func TestGetInheritedGrants(t *testing.T) {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	aclroot := newAccessList(t, "root", clock)
	acl1 := newAccessList(t, "1", clock)
	acl2 := newAccessList(t, "2", clock)

	// aclroot has a trait for owners - "root-owner-trait", and a role for owners - "root-owner-role"
	aclroot.Spec.OwnerGrants = accesslist.Grants{
		Traits: map[string][]string{
			"root-owner-trait": {"root-owner-value"},
		},
		Roles: []string{"root-owner-role"},
	}

	// acl1 has a trait for members - "1-member-trait", and a role for members - "1-member-role"
	acl1.Spec.Grants = accesslist.Grants{
		Traits: map[string][]string{
			"1-member-trait": {"1-member-value"},
		},
		Roles: []string{"1-member-role"},
	}

	// acl2 has no traits or roles
	acl2.Spec.Grants = accesslist.Grants{}

	aclroot.SetOwners([]accesslist.Owner{
		{
			Name:           acl1.GetName(),
			MembershipKind: accesslist.MembershipKindList,
		},
	})

	membersGetter := &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{
			acl1.GetName(): {newAccessListMember(t, acl1.GetName(), acl2.GetName(), accesslist.MembershipKindList, clock)},
		},
	}

	hierarchy, err := NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{aclroot, acl1, acl2},
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	// acl1 is an Owner of aclroot, and acl2 is a Member of acl1.
	// so, members of acl2 should inherit aclroot's owner grants, and acl1's member grants.
	expectedGrants := &accesslist.Grants{
		Traits: map[string][]string{
			"1-member-trait":   {"1-member-value"},
			"root-owner-trait": {"root-owner-value"},
		},
		Roles: []string{"1-member-role", "root-owner-role"},
	}

	grants, err := hierarchy.GetInheritedGrants(acl2.GetName())
	require.NoError(t, err)
	require.Equal(t, expectedGrants, grants)
}

func TestWithForcedCyclicReference(t *testing.T) {
	clock := clockwork.NewFakeClock()
	ctx := context.Background()

	acl1 := newAccessList(t, "1", clock)
	acl2 := newAccessList(t, "2", clock)
	acl3 := newAccessList(t, "3", clock)

	// acl1 -> acl3, and
	// acl1 -> acl2 -> acl1 ...
	acl1m1 := newAccessListMember(t, acl1.GetName(), acl2.GetName(), accesslist.MembershipKindList, clock)
	acl1m2 := newAccessListMember(t, acl1.GetName(), acl3.GetName(), accesslist.MembershipKindList, clock)
	acl1m3 := newAccessListMember(t, acl1.GetName(), member1, accesslist.MembershipKindUser, clock)
	acl2m1 := newAccessListMember(t, acl2.GetName(), acl1.GetName(), accesslist.MembershipKindList, clock)
	acl3m1 := newAccessListMember(t, acl3.GetName(), member2, accesslist.MembershipKindUser, clock)

	membersGetter := &mockMembersGetter{
		members: map[string][]*accesslist.AccessListMember{
			acl1.GetName(): {acl1m1, acl1m2, acl1m3},
			acl3.GetName(): {acl3m1},
		},
	}

	hierarchy, err := NewHierarchy(ctx, HierarchyConfig{
		AccessLists: []*accesslist.AccessList{acl1, acl2, acl3},
		Members:     membersGetter,
		Locks:       nil,
		Clock:       clock,
	})
	require.NoError(t, err)

	members, err := hierarchy.GetMembers(acl1.GetName())
	require.NoError(t, err)
	require.Len(t, members, 2)

	membersGetter.members[acl1.GetName()] = []*accesslist.AccessListMember{acl2m1}

	members, err = hierarchy.GetMembers(acl1.GetName())
	require.NoError(t, err)
	require.Len(t, members, 2)
}

func newAccessList(t *testing.T, name string, clock clockwork.Clock) *accesslist.AccessList {
	t.Helper()

	accessList, err := accesslist.NewAccessList(
		header.Metadata{
			Name: name,
		},
		accesslist.Spec{
			Title:       name,
			Description: "test access list",
			Owners: []accesslist.Owner{
				{Name: ownerUser, Description: "owner user", MembershipKind: accesslist.MembershipKindUser},
				{Name: ownerUser2, Description: "owner user 2", MembershipKind: accesslist.MembershipKindUser},
			},
			Audit: accesslist.Audit{
				NextAuditDate: clock.Now().Add(time.Hour * 24 * 365),
				Notifications: accesslist.Notifications{
					Start: 336 * time.Hour, // Two weeks.
				},
			},
			MembershipRequires: accesslist.Requires{
				Roles: []string{"mrole1", "mrole2"},
				Traits: map[string][]string{
					"mtrait1": {"mvalue1", "mvalue2"},
					"mtrait2": {"mvalue3", "mvalue4"},
				},
			},
			OwnershipRequires: accesslist.Requires{
				Roles: []string{"orole1", "orole2"},
				Traits: map[string][]string{
					"otrait1": {"ovalue1", "ovalue2"},
					"otrait2": {"ovalue3", "ovalue4"},
				},
			},
			Grants: accesslist.Grants{
				Roles: []string{"grole1", "grole2"},
				Traits: map[string][]string{
					"gtrait1": {"gvalue1", "gvalue2"},
					"gtrait2": {"gvalue3", "gvalue4"},
				},
			},
		},
	)
	require.NoError(t, err)

	return accessList
}

func newAccessListMember(t *testing.T, accessListName, memberName string, memberKind string, clock clockwork.Clock) *accesslist.AccessListMember {
	t.Helper()

	member, err := accesslist.NewAccessListMember(
		header.Metadata{
			Name: memberName,
		},
		accesslist.AccessListMemberSpec{
			AccessList:     accessListName,
			Name:           memberName,
			Joined:         clock.Now().UTC(),
			Expires:        clock.Now().UTC().Add(24 * time.Hour),
			Reason:         "because",
			AddedBy:        "maxim.dietz@goteleport.com",
			MembershipKind: memberKind,
		},
	)
	require.NoError(t, err)

	return member
}
