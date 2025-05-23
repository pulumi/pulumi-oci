// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSchedulerDefinitionArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSchedulerDefinitionArgs Empty = new GetSchedulerDefinitionArgs();

    /**
     * unique SchedulerDefinition identifier
     * 
     */
    @Import(name="schedulerDefinitionId", required=true)
    private Output<String> schedulerDefinitionId;

    /**
     * @return unique SchedulerDefinition identifier
     * 
     */
    public Output<String> schedulerDefinitionId() {
        return this.schedulerDefinitionId;
    }

    private GetSchedulerDefinitionArgs() {}

    private GetSchedulerDefinitionArgs(GetSchedulerDefinitionArgs $) {
        this.schedulerDefinitionId = $.schedulerDefinitionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSchedulerDefinitionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSchedulerDefinitionArgs $;

        public Builder() {
            $ = new GetSchedulerDefinitionArgs();
        }

        public Builder(GetSchedulerDefinitionArgs defaults) {
            $ = new GetSchedulerDefinitionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param schedulerDefinitionId unique SchedulerDefinition identifier
         * 
         * @return builder
         * 
         */
        public Builder schedulerDefinitionId(Output<String> schedulerDefinitionId) {
            $.schedulerDefinitionId = schedulerDefinitionId;
            return this;
        }

        /**
         * @param schedulerDefinitionId unique SchedulerDefinition identifier
         * 
         * @return builder
         * 
         */
        public Builder schedulerDefinitionId(String schedulerDefinitionId) {
            return schedulerDefinitionId(Output.of(schedulerDefinitionId));
        }

        public GetSchedulerDefinitionArgs build() {
            if ($.schedulerDefinitionId == null) {
                throw new MissingRequiredPropertyException("GetSchedulerDefinitionArgs", "schedulerDefinitionId");
            }
            return $;
        }
    }

}
