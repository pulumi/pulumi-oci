// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.GetAutonomousDatabaseRefreshableClonesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetAutonomousDatabaseRefreshableClonesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousDatabaseRefreshableClonesArgs Empty = new GetAutonomousDatabaseRefreshableClonesArgs();

    /**
     * The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="autonomousDatabaseId", required=true)
    private Output<String> autonomousDatabaseId;

    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> autonomousDatabaseId() {
        return this.autonomousDatabaseId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetAutonomousDatabaseRefreshableClonesFilterArgs>> filters;

    public Optional<Output<List<GetAutonomousDatabaseRefreshableClonesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetAutonomousDatabaseRefreshableClonesArgs() {}

    private GetAutonomousDatabaseRefreshableClonesArgs(GetAutonomousDatabaseRefreshableClonesArgs $) {
        this.autonomousDatabaseId = $.autonomousDatabaseId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousDatabaseRefreshableClonesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousDatabaseRefreshableClonesArgs $;

        public Builder() {
            $ = new GetAutonomousDatabaseRefreshableClonesArgs();
        }

        public Builder(GetAutonomousDatabaseRefreshableClonesArgs defaults) {
            $ = new GetAutonomousDatabaseRefreshableClonesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomousDatabaseId The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseId(Output<String> autonomousDatabaseId) {
            $.autonomousDatabaseId = autonomousDatabaseId;
            return this;
        }

        /**
         * @param autonomousDatabaseId The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseId(String autonomousDatabaseId) {
            return autonomousDatabaseId(Output.of(autonomousDatabaseId));
        }

        public Builder filters(@Nullable Output<List<GetAutonomousDatabaseRefreshableClonesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetAutonomousDatabaseRefreshableClonesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetAutonomousDatabaseRefreshableClonesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetAutonomousDatabaseRefreshableClonesArgs build() {
            $.autonomousDatabaseId = Objects.requireNonNull($.autonomousDatabaseId, "expected parameter 'autonomousDatabaseId' to be non-null");
            return $;
        }
    }

}