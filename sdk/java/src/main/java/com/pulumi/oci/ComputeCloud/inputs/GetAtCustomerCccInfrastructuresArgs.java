// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ComputeCloud.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ComputeCloud.inputs.GetAtCustomerCccInfrastructuresFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAtCustomerCccInfrastructuresArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAtCustomerCccInfrastructuresArgs Empty = new GetAtCustomerCccInfrastructuresArgs();

    /**
     * Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    @Import(name="accessLevel")
    private @Nullable Output<String> accessLevel;

    /**
     * @return Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
     * 
     */
    public Optional<Output<String>> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }

    /**
     * An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
     * 
     */
    @Import(name="cccInfrastructureId")
    private @Nullable Output<String> cccInfrastructureId;

    /**
     * @return An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
     * 
     */
    public Optional<Output<String>> cccInfrastructureId() {
        return Optional.ofNullable(this.cccInfrastructureId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    @Import(name="compartmentIdInSubtree")
    private @Nullable Output<Boolean> compartmentIdInSubtree;

    /**
     * @return Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    public Optional<Output<Boolean>> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * A filter to return only resources whose display name contains the substring.
     * 
     */
    @Import(name="displayNameContains")
    private @Nullable Output<String> displayNameContains;

    /**
     * @return A filter to return only resources whose display name contains the substring.
     * 
     */
    public Optional<Output<String>> displayNameContains() {
        return Optional.ofNullable(this.displayNameContains);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAtCustomerCccInfrastructuresFilterArgs>> filters;

    public Optional<Output<List<GetAtCustomerCccInfrastructuresFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter used to return only resources that match the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter used to return only resources that match the given lifecycleState.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetAtCustomerCccInfrastructuresArgs() {}

    private GetAtCustomerCccInfrastructuresArgs(GetAtCustomerCccInfrastructuresArgs $) {
        this.accessLevel = $.accessLevel;
        this.cccInfrastructureId = $.cccInfrastructureId;
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.displayName = $.displayName;
        this.displayNameContains = $.displayNameContains;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAtCustomerCccInfrastructuresArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAtCustomerCccInfrastructuresArgs $;

        public Builder() {
            $ = new GetAtCustomerCccInfrastructuresArgs();
        }

        public Builder(GetAtCustomerCccInfrastructuresArgs defaults) {
            $ = new GetAtCustomerCccInfrastructuresArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessLevel Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(@Nullable Output<String> accessLevel) {
            $.accessLevel = accessLevel;
            return this;
        }

        /**
         * @param accessLevel Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
         * 
         * @return builder
         * 
         */
        public Builder accessLevel(String accessLevel) {
            return accessLevel(Output.of(accessLevel));
        }

        /**
         * @param cccInfrastructureId An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder cccInfrastructureId(@Nullable Output<String> cccInfrastructureId) {
            $.cccInfrastructureId = cccInfrastructureId;
            return this;
        }

        /**
         * @param cccInfrastructureId An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder cccInfrastructureId(String cccInfrastructureId) {
            return cccInfrastructureId(Output.of(cccInfrastructureId));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(@Nullable Output<Boolean> compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            return compartmentIdInSubtree(Output.of(compartmentIdInSubtree));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param displayNameContains A filter to return only resources whose display name contains the substring.
         * 
         * @return builder
         * 
         */
        public Builder displayNameContains(@Nullable Output<String> displayNameContains) {
            $.displayNameContains = displayNameContains;
            return this;
        }

        /**
         * @param displayNameContains A filter to return only resources whose display name contains the substring.
         * 
         * @return builder
         * 
         */
        public Builder displayNameContains(String displayNameContains) {
            return displayNameContains(Output.of(displayNameContains));
        }

        public Builder filters(@Nullable Output<List<GetAtCustomerCccInfrastructuresFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAtCustomerCccInfrastructuresFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAtCustomerCccInfrastructuresFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter used to return only resources that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter used to return only resources that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetAtCustomerCccInfrastructuresArgs build() {
            return $;
        }
    }

}