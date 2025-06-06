// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MeteringComputation.inputs.GetScheduledRunsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetScheduledRunsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetScheduledRunsPlainArgs Empty = new GetScheduledRunsPlainArgs();

    @Import(name="filters")
    private @Nullable List<GetScheduledRunsFilter> filters;

    public Optional<List<GetScheduledRunsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The schedule unique ID.
     * 
     */
    @Import(name="scheduleId", required=true)
    private String scheduleId;

    /**
     * @return The schedule unique ID.
     * 
     */
    public String scheduleId() {
        return this.scheduleId;
    }

    private GetScheduledRunsPlainArgs() {}

    private GetScheduledRunsPlainArgs(GetScheduledRunsPlainArgs $) {
        this.filters = $.filters;
        this.scheduleId = $.scheduleId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetScheduledRunsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetScheduledRunsPlainArgs $;

        public Builder() {
            $ = new GetScheduledRunsPlainArgs();
        }

        public Builder(GetScheduledRunsPlainArgs defaults) {
            $ = new GetScheduledRunsPlainArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable List<GetScheduledRunsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetScheduledRunsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param scheduleId The schedule unique ID.
         * 
         * @return builder
         * 
         */
        public Builder scheduleId(String scheduleId) {
            $.scheduleId = scheduleId;
            return this;
        }

        public GetScheduledRunsPlainArgs build() {
            if ($.scheduleId == null) {
                throw new MissingRequiredPropertyException("GetScheduledRunsPlainArgs", "scheduleId");
            }
            return $;
        }
    }

}
