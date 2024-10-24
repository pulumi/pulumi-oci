// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class IdpGroupMappingState extends com.pulumi.resources.ResourceArgs {

    public static final IdpGroupMappingState Empty = new IdpGroupMappingState();

    /**
     * The OCID of the tenancy containing the `IdentityProvider`.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the tenancy containing the `IdentityProvider`.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     * 
     */
    @Import(name="groupId")
    private @Nullable Output<String> groupId;

    /**
     * @return (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
     * 
     */
    public Optional<Output<String>> groupId() {
        return Optional.ofNullable(this.groupId);
    }

    /**
     * The OCID of the identity provider.
     * 
     */
    @Import(name="identityProviderId")
    private @Nullable Output<String> identityProviderId;

    /**
     * @return The OCID of the identity provider.
     * 
     */
    public Optional<Output<String>> identityProviderId() {
        return Optional.ofNullable(this.identityProviderId);
    }

    /**
     * (Updatable) The name of the IdP group you want to map.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="idpGroupName")
    private @Nullable Output<String> idpGroupName;

    /**
     * @return (Updatable) The name of the IdP group you want to map.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> idpGroupName() {
        return Optional.ofNullable(this.idpGroupName);
    }

    /**
     * The detailed status of INACTIVE lifecycleState.
     * 
     */
    @Import(name="inactiveState")
    private @Nullable Output<String> inactiveState;

    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public Optional<Output<String>> inactiveState() {
        return Optional.ofNullable(this.inactiveState);
    }

    /**
     * The mapping&#39;s current state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The mapping&#39;s current state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Date and time the mapping was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return Date and time the mapping was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private IdpGroupMappingState() {}

    private IdpGroupMappingState(IdpGroupMappingState $) {
        this.compartmentId = $.compartmentId;
        this.groupId = $.groupId;
        this.identityProviderId = $.identityProviderId;
        this.idpGroupName = $.idpGroupName;
        this.inactiveState = $.inactiveState;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(IdpGroupMappingState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private IdpGroupMappingState $;

        public Builder() {
            $ = new IdpGroupMappingState();
        }

        public Builder(IdpGroupMappingState defaults) {
            $ = new IdpGroupMappingState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the tenancy containing the `IdentityProvider`.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the tenancy containing the `IdentityProvider`.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param groupId (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
         * 
         * @return builder
         * 
         */
        public Builder groupId(@Nullable Output<String> groupId) {
            $.groupId = groupId;
            return this;
        }

        /**
         * @param groupId (Updatable) The OCID of the IAM Service [group](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/Group/) you want to map to the IdP group.
         * 
         * @return builder
         * 
         */
        public Builder groupId(String groupId) {
            return groupId(Output.of(groupId));
        }

        /**
         * @param identityProviderId The OCID of the identity provider.
         * 
         * @return builder
         * 
         */
        public Builder identityProviderId(@Nullable Output<String> identityProviderId) {
            $.identityProviderId = identityProviderId;
            return this;
        }

        /**
         * @param identityProviderId The OCID of the identity provider.
         * 
         * @return builder
         * 
         */
        public Builder identityProviderId(String identityProviderId) {
            return identityProviderId(Output.of(identityProviderId));
        }

        /**
         * @param idpGroupName (Updatable) The name of the IdP group you want to map.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder idpGroupName(@Nullable Output<String> idpGroupName) {
            $.idpGroupName = idpGroupName;
            return this;
        }

        /**
         * @param idpGroupName (Updatable) The name of the IdP group you want to map.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder idpGroupName(String idpGroupName) {
            return idpGroupName(Output.of(idpGroupName));
        }

        /**
         * @param inactiveState The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder inactiveState(@Nullable Output<String> inactiveState) {
            $.inactiveState = inactiveState;
            return this;
        }

        /**
         * @param inactiveState The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder inactiveState(String inactiveState) {
            return inactiveState(Output.of(inactiveState));
        }

        /**
         * @param state The mapping&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The mapping&#39;s current state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated Date and time the mapping was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated Date and time the mapping was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public IdpGroupMappingState build() {
            return $;
        }
    }

}
