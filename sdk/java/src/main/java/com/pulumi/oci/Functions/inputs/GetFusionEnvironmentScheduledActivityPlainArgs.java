// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetFusionEnvironmentScheduledActivityPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFusionEnvironmentScheduledActivityPlainArgs Empty = new GetFusionEnvironmentScheduledActivityPlainArgs();

    /**
     * unique FusionEnvironment identifier
     * 
     */
    @Import(name="fusionEnvironmentId", required=true)
    private String fusionEnvironmentId;

    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    public String fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }

    /**
     * Unique ScheduledActivity identifier.
     * 
     */
    @Import(name="scheduledActivityId", required=true)
    private String scheduledActivityId;

    /**
     * @return Unique ScheduledActivity identifier.
     * 
     */
    public String scheduledActivityId() {
        return this.scheduledActivityId;
    }

    private GetFusionEnvironmentScheduledActivityPlainArgs() {}

    private GetFusionEnvironmentScheduledActivityPlainArgs(GetFusionEnvironmentScheduledActivityPlainArgs $) {
        this.fusionEnvironmentId = $.fusionEnvironmentId;
        this.scheduledActivityId = $.scheduledActivityId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFusionEnvironmentScheduledActivityPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFusionEnvironmentScheduledActivityPlainArgs $;

        public Builder() {
            $ = new GetFusionEnvironmentScheduledActivityPlainArgs();
        }

        public Builder(GetFusionEnvironmentScheduledActivityPlainArgs defaults) {
            $ = new GetFusionEnvironmentScheduledActivityPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            $.fusionEnvironmentId = fusionEnvironmentId;
            return this;
        }

        /**
         * @param scheduledActivityId Unique ScheduledActivity identifier.
         * 
         * @return builder
         * 
         */
        public Builder scheduledActivityId(String scheduledActivityId) {
            $.scheduledActivityId = scheduledActivityId;
            return this;
        }

        public GetFusionEnvironmentScheduledActivityPlainArgs build() {
            if ($.fusionEnvironmentId == null) {
                throw new MissingRequiredPropertyException("GetFusionEnvironmentScheduledActivityPlainArgs", "fusionEnvironmentId");
            }
            if ($.scheduledActivityId == null) {
                throw new MissingRequiredPropertyException("GetFusionEnvironmentScheduledActivityPlainArgs", "scheduledActivityId");
            }
            return $;
        }
    }

}
