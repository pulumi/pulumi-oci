// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FleetAppsManagement.inputs.GetComplianceRecordCountsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetComplianceRecordCountsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetComplianceRecordCountsArgs Empty = new GetComplianceRecordCountsArgs();

    /**
     * The ID of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The ID of the compartment in which to list resources.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetComplianceRecordCountsFilterArgs>> filters;

    public Optional<Output<List<GetComplianceRecordCountsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetComplianceRecordCountsArgs() {}

    private GetComplianceRecordCountsArgs(GetComplianceRecordCountsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetComplianceRecordCountsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetComplianceRecordCountsArgs $;

        public Builder() {
            $ = new GetComplianceRecordCountsArgs();
        }

        public Builder(GetComplianceRecordCountsArgs defaults) {
            $ = new GetComplianceRecordCountsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The ID of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetComplianceRecordCountsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetComplianceRecordCountsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetComplianceRecordCountsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetComplianceRecordCountsArgs build() {
            return $;
        }
    }

}
