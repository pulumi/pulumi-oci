// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetModelDeploymentCategoryLogDetailPredict {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a log group to work with.
     * 
     */
    private String logGroupId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a log to work with.
     * 
     */
    private String logId;

    private GetModelDeploymentCategoryLogDetailPredict() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a log group to work with.
     * 
     */
    public String logGroupId() {
        return this.logGroupId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a log to work with.
     * 
     */
    public String logId() {
        return this.logId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelDeploymentCategoryLogDetailPredict defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String logGroupId;
        private String logId;
        public Builder() {}
        public Builder(GetModelDeploymentCategoryLogDetailPredict defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.logGroupId = defaults.logGroupId;
    	      this.logId = defaults.logId;
        }

        @CustomType.Setter
        public Builder logGroupId(String logGroupId) {
            this.logGroupId = Objects.requireNonNull(logGroupId);
            return this;
        }
        @CustomType.Setter
        public Builder logId(String logId) {
            this.logId = Objects.requireNonNull(logId);
            return this;
        }
        public GetModelDeploymentCategoryLogDetailPredict build() {
            final var o = new GetModelDeploymentCategoryLogDetailPredict();
            o.logGroupId = logGroupId;
            o.logId = logId;
            return o;
        }
    }
}