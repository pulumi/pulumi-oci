// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetFusionEnvironmentScheduledActivityArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFusionEnvironmentScheduledActivityArgs Empty = new GetFusionEnvironmentScheduledActivityArgs();

    /**
     * unique FusionEnvironment identifier
     * 
     */
    @Import(name="fusionEnvironmentId", required=true)
    private Output<String> fusionEnvironmentId;

    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    public Output<String> fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }

    /**
     * Unique ScheduledActivity identifier.
     * 
     */
    @Import(name="scheduledActivityId", required=true)
    private Output<String> scheduledActivityId;

    /**
     * @return Unique ScheduledActivity identifier.
     * 
     */
    public Output<String> scheduledActivityId() {
        return this.scheduledActivityId;
    }

    private GetFusionEnvironmentScheduledActivityArgs() {}

    private GetFusionEnvironmentScheduledActivityArgs(GetFusionEnvironmentScheduledActivityArgs $) {
        this.fusionEnvironmentId = $.fusionEnvironmentId;
        this.scheduledActivityId = $.scheduledActivityId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFusionEnvironmentScheduledActivityArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFusionEnvironmentScheduledActivityArgs $;

        public Builder() {
            $ = new GetFusionEnvironmentScheduledActivityArgs();
        }

        public Builder(GetFusionEnvironmentScheduledActivityArgs defaults) {
            $ = new GetFusionEnvironmentScheduledActivityArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(Output<String> fusionEnvironmentId) {
            $.fusionEnvironmentId = fusionEnvironmentId;
            return this;
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            return fusionEnvironmentId(Output.of(fusionEnvironmentId));
        }

        /**
         * @param scheduledActivityId Unique ScheduledActivity identifier.
         * 
         * @return builder
         * 
         */
        public Builder scheduledActivityId(Output<String> scheduledActivityId) {
            $.scheduledActivityId = scheduledActivityId;
            return this;
        }

        /**
         * @param scheduledActivityId Unique ScheduledActivity identifier.
         * 
         * @return builder
         * 
         */
        public Builder scheduledActivityId(String scheduledActivityId) {
            return scheduledActivityId(Output.of(scheduledActivityId));
        }

        public GetFusionEnvironmentScheduledActivityArgs build() {
            if ($.fusionEnvironmentId == null) {
                throw new MissingRequiredPropertyException("GetFusionEnvironmentScheduledActivityArgs", "fusionEnvironmentId");
            }
            if ($.scheduledActivityId == null) {
                throw new MissingRequiredPropertyException("GetFusionEnvironmentScheduledActivityArgs", "scheduledActivityId");
            }
            return $;
        }
    }

}
