// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetScheduleArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetScheduleArgs Empty = new GetScheduleArgs();

    /**
     * The schedule unique OCID.
     * 
     */
    @Import(name="scheduleId", required=true)
    private Output<String> scheduleId;

    /**
     * @return The schedule unique OCID.
     * 
     */
    public Output<String> scheduleId() {
        return this.scheduleId;
    }

    private GetScheduleArgs() {}

    private GetScheduleArgs(GetScheduleArgs $) {
        this.scheduleId = $.scheduleId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetScheduleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetScheduleArgs $;

        public Builder() {
            $ = new GetScheduleArgs();
        }

        public Builder(GetScheduleArgs defaults) {
            $ = new GetScheduleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param scheduleId The schedule unique OCID.
         * 
         * @return builder
         * 
         */
        public Builder scheduleId(Output<String> scheduleId) {
            $.scheduleId = scheduleId;
            return this;
        }

        /**
         * @param scheduleId The schedule unique OCID.
         * 
         * @return builder
         * 
         */
        public Builder scheduleId(String scheduleId) {
            return scheduleId(Output.of(scheduleId));
        }

        public GetScheduleArgs build() {
            $.scheduleId = Objects.requireNonNull($.scheduleId, "expected parameter 'scheduleId' to be non-null");
            return $;
        }
    }

}