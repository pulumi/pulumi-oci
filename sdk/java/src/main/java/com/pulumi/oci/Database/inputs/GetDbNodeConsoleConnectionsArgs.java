// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.GetDbNodeConsoleConnectionsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDbNodeConsoleConnectionsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbNodeConsoleConnectionsArgs Empty = new GetDbNodeConsoleConnectionsArgs();

    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbNodeId", required=true)
    private Output<String> dbNodeId;

    /**
     * @return The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> dbNodeId() {
        return this.dbNodeId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDbNodeConsoleConnectionsFilterArgs>> filters;

    public Optional<Output<List<GetDbNodeConsoleConnectionsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetDbNodeConsoleConnectionsArgs() {}

    private GetDbNodeConsoleConnectionsArgs(GetDbNodeConsoleConnectionsArgs $) {
        this.dbNodeId = $.dbNodeId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbNodeConsoleConnectionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbNodeConsoleConnectionsArgs $;

        public Builder() {
            $ = new GetDbNodeConsoleConnectionsArgs();
        }

        public Builder(GetDbNodeConsoleConnectionsArgs defaults) {
            $ = new GetDbNodeConsoleConnectionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dbNodeId The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbNodeId(Output<String> dbNodeId) {
            $.dbNodeId = dbNodeId;
            return this;
        }

        /**
         * @param dbNodeId The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbNodeId(String dbNodeId) {
            return dbNodeId(Output.of(dbNodeId));
        }

        public Builder filters(@Nullable Output<List<GetDbNodeConsoleConnectionsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDbNodeConsoleConnectionsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDbNodeConsoleConnectionsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetDbNodeConsoleConnectionsArgs build() {
            $.dbNodeId = Objects.requireNonNull($.dbNodeId, "expected parameter 'dbNodeId' to be non-null");
            return $;
        }
    }

}