// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetAuditProfileAnalyticItemDimension {
    /**
     * @return Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database, potentially incurring additional charges. The default value is inherited from the global settings.  You can change at the global level or at the target level.
     * 
     */
    private Boolean isPaidUsageEnabled;

    private GetAuditProfileAnalyticItemDimension() {}
    /**
     * @return Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database, potentially incurring additional charges. The default value is inherited from the global settings.  You can change at the global level or at the target level.
     * 
     */
    public Boolean isPaidUsageEnabled() {
        return this.isPaidUsageEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAuditProfileAnalyticItemDimension defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isPaidUsageEnabled;
        public Builder() {}
        public Builder(GetAuditProfileAnalyticItemDimension defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isPaidUsageEnabled = defaults.isPaidUsageEnabled;
        }

        @CustomType.Setter
        public Builder isPaidUsageEnabled(Boolean isPaidUsageEnabled) {
            this.isPaidUsageEnabled = Objects.requireNonNull(isPaidUsageEnabled);
            return this;
        }
        public GetAuditProfileAnalyticItemDimension build() {
            final var o = new GetAuditProfileAnalyticItemDimension();
            o.isPaidUsageEnabled = isPaidUsageEnabled;
            return o;
        }
    }
}