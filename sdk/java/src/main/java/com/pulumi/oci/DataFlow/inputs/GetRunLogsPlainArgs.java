// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataFlow.inputs.GetRunLogsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRunLogsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRunLogsPlainArgs Empty = new GetRunLogsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetRunLogsFilter> filters;

    public Optional<List<GetRunLogsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The unique ID for the run
     * 
     */
    @Import(name="runId", required=true)
    private String runId;

    /**
     * @return The unique ID for the run
     * 
     */
    public String runId() {
        return this.runId;
    }

    private GetRunLogsPlainArgs() {}

    private GetRunLogsPlainArgs(GetRunLogsPlainArgs $) {
        this.filters = $.filters;
        this.runId = $.runId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRunLogsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRunLogsPlainArgs $;

        public Builder() {
            $ = new GetRunLogsPlainArgs();
        }

        public Builder(GetRunLogsPlainArgs defaults) {
            $ = new GetRunLogsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetRunLogsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetRunLogsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param runId The unique ID for the run
         * 
         * @return builder
         * 
         */
        public Builder runId(String runId) {
            $.runId = runId;
            return this;
        }

        public GetRunLogsPlainArgs build() {
            $.runId = Objects.requireNonNull($.runId, "expected parameter 'runId' to be non-null");
            return $;
        }
    }

}