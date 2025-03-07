// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.FleetAppsManagement.inputs.GetManagedEntityCountsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedEntityCountsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedEntityCountsArgs Empty = new GetManagedEntityCountsArgs();

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
    private @Nullable Output<List<GetManagedEntityCountsFilterArgs>> filters;

    public Optional<Output<List<GetManagedEntityCountsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetManagedEntityCountsArgs() {}

    private GetManagedEntityCountsArgs(GetManagedEntityCountsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedEntityCountsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedEntityCountsArgs $;

        public Builder() {
            $ = new GetManagedEntityCountsArgs();
        }

        public Builder(GetManagedEntityCountsArgs defaults) {
            $ = new GetManagedEntityCountsArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable Output<List<GetManagedEntityCountsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetManagedEntityCountsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetManagedEntityCountsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetManagedEntityCountsArgs build() {
            return $;
        }
    }

}
