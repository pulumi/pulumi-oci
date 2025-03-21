// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAssignedSubscriptionPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAssignedSubscriptionPlainArgs Empty = new GetAssignedSubscriptionPlainArgs();

    /**
     * OCID of the assigned Oracle Cloud Subscription.
     * 
     */
    @Import(name="assignedSubscriptionId", required=true)
    private String assignedSubscriptionId;

    /**
     * @return OCID of the assigned Oracle Cloud Subscription.
     * 
     */
    public String assignedSubscriptionId() {
        return this.assignedSubscriptionId;
    }

    private GetAssignedSubscriptionPlainArgs() {}

    private GetAssignedSubscriptionPlainArgs(GetAssignedSubscriptionPlainArgs $) {
        this.assignedSubscriptionId = $.assignedSubscriptionId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAssignedSubscriptionPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAssignedSubscriptionPlainArgs $;

        public Builder() {
            $ = new GetAssignedSubscriptionPlainArgs();
        }

        public Builder(GetAssignedSubscriptionPlainArgs defaults) {
            $ = new GetAssignedSubscriptionPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param assignedSubscriptionId OCID of the assigned Oracle Cloud Subscription.
         * 
         * @return builder
         * 
         */
        public Builder assignedSubscriptionId(String assignedSubscriptionId) {
            $.assignedSubscriptionId = assignedSubscriptionId;
            return this;
        }

        public GetAssignedSubscriptionPlainArgs build() {
            if ($.assignedSubscriptionId == null) {
                throw new MissingRequiredPropertyException("GetAssignedSubscriptionPlainArgs", "assignedSubscriptionId");
            }
            return $;
        }
    }

}
