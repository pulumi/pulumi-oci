// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.inputs.GetUserGroupMembershipsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetUserGroupMembershipsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetUserGroupMembershipsArgs Empty = new GetUserGroupMembershipsArgs();

    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetUserGroupMembershipsFilterArgs>> filters;

    public Optional<Output<List<GetUserGroupMembershipsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The OCID of the group.
     * 
     */
    @Import(name="groupId")
    private @Nullable Output<String> groupId;

    /**
     * @return The OCID of the group.
     * 
     */
    public Optional<Output<String>> groupId() {
        return Optional.ofNullable(this.groupId);
    }

    /**
     * The OCID of the user.
     * 
     */
    @Import(name="userId")
    private @Nullable Output<String> userId;

    /**
     * @return The OCID of the user.
     * 
     */
    public Optional<Output<String>> userId() {
        return Optional.ofNullable(this.userId);
    }

    private GetUserGroupMembershipsArgs() {}

    private GetUserGroupMembershipsArgs(GetUserGroupMembershipsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.groupId = $.groupId;
        this.userId = $.userId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetUserGroupMembershipsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetUserGroupMembershipsArgs $;

        public Builder() {
            $ = new GetUserGroupMembershipsArgs();
        }

        public Builder(GetUserGroupMembershipsArgs defaults) {
            $ = new GetUserGroupMembershipsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment (remember that the tenancy is simply the root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment (remember that the tenancy is simply the root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetUserGroupMembershipsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetUserGroupMembershipsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetUserGroupMembershipsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param groupId The OCID of the group.
         * 
         * @return builder
         * 
         */
        public Builder groupId(@Nullable Output<String> groupId) {
            $.groupId = groupId;
            return this;
        }

        /**
         * @param groupId The OCID of the group.
         * 
         * @return builder
         * 
         */
        public Builder groupId(String groupId) {
            return groupId(Output.of(groupId));
        }

        /**
         * @param userId The OCID of the user.
         * 
         * @return builder
         * 
         */
        public Builder userId(@Nullable Output<String> userId) {
            $.userId = userId;
            return this;
        }

        /**
         * @param userId The OCID of the user.
         * 
         * @return builder
         * 
         */
        public Builder userId(String userId) {
            return userId(Output.of(userId));
        }

        public GetUserGroupMembershipsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetUserGroupMembershipsArgs", "compartmentId");
            }
            return $;
        }
    }

}
