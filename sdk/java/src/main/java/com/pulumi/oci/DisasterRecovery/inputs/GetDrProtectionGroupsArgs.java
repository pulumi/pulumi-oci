// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DisasterRecovery.inputs.GetDrProtectionGroupsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDrProtectionGroupsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDrProtectionGroupsArgs Empty = new GetDrProtectionGroupsArgs();

    /**
     * The ID (OCID) of the compartment in which to list resources.  Example: `ocid1.compartment.oc1..exampleocid1`
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The ID (OCID) of the compartment in which to list resources.  Example: `ocid1.compartment.oc1..exampleocid1`
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The OCID of the DR Protection Group. Optional query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
     * 
     */
    @Import(name="drProtectionGroupId")
    private @Nullable Output<String> drProtectionGroupId;

    /**
     * @return The OCID of the DR Protection Group. Optional query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
     * 
     */
    public Optional<Output<String>> drProtectionGroupId() {
        return Optional.ofNullable(this.drProtectionGroupId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDrProtectionGroupsFilterArgs>> filters;

    public Optional<Output<List<GetDrProtectionGroupsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only DR Protection Groups that match the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only DR Protection Groups that match the given lifecycleState.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetDrProtectionGroupsArgs() {}

    private GetDrProtectionGroupsArgs(GetDrProtectionGroupsArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.drProtectionGroupId = $.drProtectionGroupId;
        this.filters = $.filters;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDrProtectionGroupsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDrProtectionGroupsArgs $;

        public Builder() {
            $ = new GetDrProtectionGroupsArgs();
        }

        public Builder(GetDrProtectionGroupsArgs defaults) {
            $ = new GetDrProtectionGroupsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID (OCID) of the compartment in which to list resources.  Example: `ocid1.compartment.oc1..exampleocid1`
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID (OCID) of the compartment in which to list resources.  Example: `ocid1.compartment.oc1..exampleocid1`
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param drProtectionGroupId The OCID of the DR Protection Group. Optional query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
         * 
         * @return builder
         * 
         */
        public Builder drProtectionGroupId(@Nullable Output<String> drProtectionGroupId) {
            $.drProtectionGroupId = drProtectionGroupId;
            return this;
        }

        /**
         * @param drProtectionGroupId The OCID of the DR Protection Group. Optional query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
         * 
         * @return builder
         * 
         */
        public Builder drProtectionGroupId(String drProtectionGroupId) {
            return drProtectionGroupId(Output.of(drProtectionGroupId));
        }

        public Builder filters(@Nullable Output<List<GetDrProtectionGroupsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDrProtectionGroupsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDrProtectionGroupsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to return only DR Protection Groups that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only DR Protection Groups that match the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetDrProtectionGroupsArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}