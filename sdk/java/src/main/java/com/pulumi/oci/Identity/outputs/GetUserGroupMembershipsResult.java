// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetUserGroupMembershipsFilter;
import com.pulumi.oci.Identity.outputs.GetUserGroupMembershipsMembership;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetUserGroupMembershipsResult {
    /**
     * @return The OCID of the tenancy containing the user, group, and membership object.
     * 
     */
    private final String compartmentId;
    private final @Nullable List<GetUserGroupMembershipsFilter> filters;
    /**
     * @return The OCID of the group.
     * 
     */
    private final @Nullable String groupId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of memberships.
     * 
     */
    private final List<GetUserGroupMembershipsMembership> memberships;
    /**
     * @return The OCID of the user.
     * 
     */
    private final @Nullable String userId;

    @CustomType.Constructor
    private GetUserGroupMembershipsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetUserGroupMembershipsFilter> filters,
        @CustomType.Parameter("groupId") @Nullable String groupId,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("memberships") List<GetUserGroupMembershipsMembership> memberships,
        @CustomType.Parameter("userId") @Nullable String userId) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.groupId = groupId;
        this.id = id;
        this.memberships = memberships;
        this.userId = userId;
    }

    /**
     * @return The OCID of the tenancy containing the user, group, and membership object.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetUserGroupMembershipsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The OCID of the group.
     * 
     */
    public Optional<String> groupId() {
        return Optional.ofNullable(this.groupId);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of memberships.
     * 
     */
    public List<GetUserGroupMembershipsMembership> memberships() {
        return this.memberships;
    }
    /**
     * @return The OCID of the user.
     * 
     */
    public Optional<String> userId() {
        return Optional.ofNullable(this.userId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUserGroupMembershipsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetUserGroupMembershipsFilter> filters;
        private @Nullable String groupId;
        private String id;
        private List<GetUserGroupMembershipsMembership> memberships;
        private @Nullable String userId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetUserGroupMembershipsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.groupId = defaults.groupId;
    	      this.id = defaults.id;
    	      this.memberships = defaults.memberships;
    	      this.userId = defaults.userId;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetUserGroupMembershipsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetUserGroupMembershipsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder groupId(@Nullable String groupId) {
            this.groupId = groupId;
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder memberships(List<GetUserGroupMembershipsMembership> memberships) {
            this.memberships = Objects.requireNonNull(memberships);
            return this;
        }
        public Builder memberships(GetUserGroupMembershipsMembership... memberships) {
            return memberships(List.of(memberships));
        }
        public Builder userId(@Nullable String userId) {
            this.userId = userId;
            return this;
        }        public GetUserGroupMembershipsResult build() {
            return new GetUserGroupMembershipsResult(compartmentId, filters, groupId, id, memberships, userId);
        }
    }
}
