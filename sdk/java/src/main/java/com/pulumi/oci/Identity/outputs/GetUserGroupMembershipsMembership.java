// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetUserGroupMembershipsMembership {
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    private String compartmentId;
    /**
     * @return The OCID of the group.
     * 
     */
    private String groupId;
    /**
     * @return The OCID of the membership.
     * 
     */
    private String id;
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    private String inactiveState;
    /**
     * @return The membership&#39;s current state.
     * 
     */
    private String state;
    /**
     * @return Date and time the membership was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The OCID of the user.
     * 
     */
    private String userId;

    private GetUserGroupMembershipsMembership() {}
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The OCID of the group.
     * 
     */
    public String groupId() {
        return this.groupId;
    }
    /**
     * @return The OCID of the membership.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public String inactiveState() {
        return this.inactiveState;
    }
    /**
     * @return The membership&#39;s current state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Date and time the membership was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The OCID of the user.
     * 
     */
    public String userId() {
        return this.userId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUserGroupMembershipsMembership defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String groupId;
        private String id;
        private String inactiveState;
        private String state;
        private String timeCreated;
        private String userId;
        public Builder() {}
        public Builder(GetUserGroupMembershipsMembership defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.groupId = defaults.groupId;
    	      this.id = defaults.id;
    	      this.inactiveState = defaults.inactiveState;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.userId = defaults.userId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder groupId(String groupId) {
            this.groupId = Objects.requireNonNull(groupId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder inactiveState(String inactiveState) {
            this.inactiveState = Objects.requireNonNull(inactiveState);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder userId(String userId) {
            this.userId = Objects.requireNonNull(userId);
            return this;
        }
        public GetUserGroupMembershipsMembership build() {
            final var o = new GetUserGroupMembershipsMembership();
            o.compartmentId = compartmentId;
            o.groupId = groupId;
            o.id = id;
            o.inactiveState = inactiveState;
            o.state = state;
            o.timeCreated = timeCreated;
            o.userId = userId;
            return o;
        }
    }
}