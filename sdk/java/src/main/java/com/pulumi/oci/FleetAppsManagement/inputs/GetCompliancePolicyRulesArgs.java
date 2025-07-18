// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FleetAppsManagement.inputs.GetCompliancePolicyRulesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetCompliancePolicyRulesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetCompliancePolicyRulesArgs Empty = new GetCompliancePolicyRulesArgs();

    /**
     * The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * unique CompliancePolicy identifier.
     * 
     */
    @Import(name="compliancePolicyId")
    private @Nullable Output<String> compliancePolicyId;

    /**
     * @return unique CompliancePolicy identifier.
     * 
     */
    public Optional<Output<String>> compliancePolicyId() {
        return Optional.ofNullable(this.compliancePolicyId);
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

    @Import(name="filters")
    private @Nullable Output<List<GetCompliancePolicyRulesFilterArgs>> filters;

    public Optional<Output<List<GetCompliancePolicyRulesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique identifier or OCID for listing a single Compliance Policy Rule by id. Either compartmentId or id must be provided.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return Unique identifier or OCID for listing a single Compliance Policy Rule by id. Either compartmentId or id must be provided.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only resources that match the patch selection against the given patch name.
     * 
     */
    @Import(name="patchName")
    private @Nullable Output<String> patchName;

    /**
     * @return A filter to return only resources that match the patch selection against the given patch name.
     * 
     */
    public Optional<Output<String>> patchName() {
        return Optional.ofNullable(this.patchName);
    }

    /**
     * A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetCompliancePolicyRulesArgs() {}

    private GetCompliancePolicyRulesArgs(GetCompliancePolicyRulesArgs $) {
        this.compartmentId = $.compartmentId;
        this.compliancePolicyId = $.compliancePolicyId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.patchName = $.patchName;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetCompliancePolicyRulesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetCompliancePolicyRulesArgs $;

        public Builder() {
            $ = new GetCompliancePolicyRulesArgs();
        }

        public Builder(GetCompliancePolicyRulesArgs defaults) {
            $ = new GetCompliancePolicyRulesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources. Empty only if the resource OCID query param is not specified.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compliancePolicyId unique CompliancePolicy identifier.
         * 
         * @return builder
         * 
         */
        public Builder compliancePolicyId(@Nullable Output<String> compliancePolicyId) {
            $.compliancePolicyId = compliancePolicyId;
            return this;
        }

        /**
         * @param compliancePolicyId unique CompliancePolicy identifier.
         * 
         * @return builder
         * 
         */
        public Builder compliancePolicyId(String compliancePolicyId) {
            return compliancePolicyId(Output.of(compliancePolicyId));
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

        public Builder filters(@Nullable Output<List<GetCompliancePolicyRulesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetCompliancePolicyRulesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetCompliancePolicyRulesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id Unique identifier or OCID for listing a single Compliance Policy Rule by id. Either compartmentId or id must be provided.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id Unique identifier or OCID for listing a single Compliance Policy Rule by id. Either compartmentId or id must be provided.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param patchName A filter to return only resources that match the patch selection against the given patch name.
         * 
         * @return builder
         * 
         */
        public Builder patchName(@Nullable Output<String> patchName) {
            $.patchName = patchName;
            return this;
        }

        /**
         * @param patchName A filter to return only resources that match the patch selection against the given patch name.
         * 
         * @return builder
         * 
         */
        public Builder patchName(String patchName) {
            return patchName(Output.of(patchName));
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetCompliancePolicyRulesArgs build() {
            return $;
        }
    }

}
