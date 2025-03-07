// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSchedulingPlanArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSchedulingPlanArgs Empty = new GetSchedulingPlanArgs();

    /**
     * The Schedule Plan [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="schedulingPlanId", required=true)
    private Output<String> schedulingPlanId;

    /**
     * @return The Schedule Plan [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> schedulingPlanId() {
        return this.schedulingPlanId;
    }

    private GetSchedulingPlanArgs() {}

    private GetSchedulingPlanArgs(GetSchedulingPlanArgs $) {
        this.schedulingPlanId = $.schedulingPlanId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSchedulingPlanArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSchedulingPlanArgs $;

        public Builder() {
            $ = new GetSchedulingPlanArgs();
        }

        public Builder(GetSchedulingPlanArgs defaults) {
            $ = new GetSchedulingPlanArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param schedulingPlanId The Schedule Plan [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder schedulingPlanId(Output<String> schedulingPlanId) {
            $.schedulingPlanId = schedulingPlanId;
            return this;
        }

        /**
         * @param schedulingPlanId The Schedule Plan [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder schedulingPlanId(String schedulingPlanId) {
            return schedulingPlanId(Output.of(schedulingPlanId));
        }

        public GetSchedulingPlanArgs build() {
            if ($.schedulingPlanId == null) {
                throw new MissingRequiredPropertyException("GetSchedulingPlanArgs", "schedulingPlanId");
            }
            return $;
        }
    }

}
