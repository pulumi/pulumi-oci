// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetSchedulingPolicyArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSchedulingPolicyArgs Empty = new GetSchedulingPolicyArgs();

    /**
     * The Scheduling Policy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="schedulingPolicyId", required=true)
    private Output<String> schedulingPolicyId;

    /**
     * @return The Scheduling Policy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> schedulingPolicyId() {
        return this.schedulingPolicyId;
    }

    private GetSchedulingPolicyArgs() {}

    private GetSchedulingPolicyArgs(GetSchedulingPolicyArgs $) {
        this.schedulingPolicyId = $.schedulingPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSchedulingPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSchedulingPolicyArgs $;

        public Builder() {
            $ = new GetSchedulingPolicyArgs();
        }

        public Builder(GetSchedulingPolicyArgs defaults) {
            $ = new GetSchedulingPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param schedulingPolicyId The Scheduling Policy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder schedulingPolicyId(Output<String> schedulingPolicyId) {
            $.schedulingPolicyId = schedulingPolicyId;
            return this;
        }

        /**
         * @param schedulingPolicyId The Scheduling Policy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder schedulingPolicyId(String schedulingPolicyId) {
            return schedulingPolicyId(Output.of(schedulingPolicyId));
        }

        public GetSchedulingPolicyArgs build() {
            if ($.schedulingPolicyId == null) {
                throw new MissingRequiredPropertyException("GetSchedulingPolicyArgs", "schedulingPolicyId");
            }
            return $;
        }
    }

}
