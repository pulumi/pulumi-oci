// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetScheduledRunArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetScheduledRunArgs Empty = new GetScheduledRunArgs();

    /**
     * The scheduledRun unique OCID.
     * 
     */
    @Import(name="scheduledRunId", required=true)
    private Output<String> scheduledRunId;

    /**
     * @return The scheduledRun unique OCID.
     * 
     */
    public Output<String> scheduledRunId() {
        return this.scheduledRunId;
    }

    private GetScheduledRunArgs() {}

    private GetScheduledRunArgs(GetScheduledRunArgs $) {
        this.scheduledRunId = $.scheduledRunId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetScheduledRunArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetScheduledRunArgs $;

        public Builder() {
            $ = new GetScheduledRunArgs();
        }

        public Builder(GetScheduledRunArgs defaults) {
            $ = new GetScheduledRunArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param scheduledRunId The scheduledRun unique OCID.
         * 
         * @return builder
         * 
         */
        public Builder scheduledRunId(Output<String> scheduledRunId) {
            $.scheduledRunId = scheduledRunId;
            return this;
        }

        /**
         * @param scheduledRunId The scheduledRun unique OCID.
         * 
         * @return builder
         * 
         */
        public Builder scheduledRunId(String scheduledRunId) {
            return scheduledRunId(Output.of(scheduledRunId));
        }

        public GetScheduledRunArgs build() {
            $.scheduledRunId = Objects.requireNonNull($.scheduledRunId, "expected parameter 'scheduledRunId' to be non-null");
            return $;
        }
    }

}