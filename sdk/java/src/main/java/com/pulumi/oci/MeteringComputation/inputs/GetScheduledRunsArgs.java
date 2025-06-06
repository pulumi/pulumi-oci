// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MeteringComputation.inputs.GetScheduledRunsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetScheduledRunsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetScheduledRunsArgs Empty = new GetScheduledRunsArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetScheduledRunsFilterArgs>> filters;

    public Optional<Output<List<GetScheduledRunsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The schedule unique ID.
     * 
     */
    @Import(name="scheduleId", required=true)
    private Output<String> scheduleId;

    /**
     * @return The schedule unique ID.
     * 
     */
    public Output<String> scheduleId() {
        return this.scheduleId;
    }

    private GetScheduledRunsArgs() {}

    private GetScheduledRunsArgs(GetScheduledRunsArgs $) {
        this.filters = $.filters;
        this.scheduleId = $.scheduleId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetScheduledRunsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetScheduledRunsArgs $;

        public Builder() {
            $ = new GetScheduledRunsArgs();
        }

        public Builder(GetScheduledRunsArgs defaults) {
            $ = new GetScheduledRunsArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetScheduledRunsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetScheduledRunsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetScheduledRunsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param scheduleId The schedule unique ID.
         * 
         * @return builder
         * 
         */
        public Builder scheduleId(Output<String> scheduleId) {
            $.scheduleId = scheduleId;
            return this;
        }

        /**
         * @param scheduleId The schedule unique ID.
         * 
         * @return builder
         * 
         */
        public Builder scheduleId(String scheduleId) {
            return scheduleId(Output.of(scheduleId));
        }

        public GetScheduledRunsArgs build() {
            if ($.scheduleId == null) {
                throw new MissingRequiredPropertyException("GetScheduledRunsArgs", "scheduleId");
            }
            return $;
        }
    }

}
