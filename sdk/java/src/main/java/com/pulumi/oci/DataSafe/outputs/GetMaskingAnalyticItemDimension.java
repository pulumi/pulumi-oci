// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMaskingAnalyticItemDimension {
    /**
     * @return The OCID of the masking policy..
     * 
     */
    private String policyId;
    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    private String targetId;

    private GetMaskingAnalyticItemDimension() {}
    /**
     * @return The OCID of the masking policy..
     * 
     */
    public String policyId() {
        return this.policyId;
    }
    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    public String targetId() {
        return this.targetId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMaskingAnalyticItemDimension defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String policyId;
        private String targetId;
        public Builder() {}
        public Builder(GetMaskingAnalyticItemDimension defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.policyId = defaults.policyId;
    	      this.targetId = defaults.targetId;
        }

        @CustomType.Setter
        public Builder policyId(String policyId) {
            this.policyId = Objects.requireNonNull(policyId);
            return this;
        }
        @CustomType.Setter
        public Builder targetId(String targetId) {
            this.targetId = Objects.requireNonNull(targetId);
            return this;
        }
        public GetMaskingAnalyticItemDimension build() {
            final var o = new GetMaskingAnalyticItemDimension();
            o.policyId = policyId;
            o.targetId = targetId;
            return o;
        }
    }
}