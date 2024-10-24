// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionItemDimension {
    /**
     * @return A filter to return only the resources that match the specified sensitive data model OCID.
     * 
     */
    private String sensitiveDataModelId;
    /**
     * @return A filter to return only items related to a specific sensitive type OCID.
     * 
     */
    private String sensitiveTypeId;
    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    private String targetId;

    private GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionItemDimension() {}
    /**
     * @return A filter to return only the resources that match the specified sensitive data model OCID.
     * 
     */
    public String sensitiveDataModelId() {
        return this.sensitiveDataModelId;
    }
    /**
     * @return A filter to return only items related to a specific sensitive type OCID.
     * 
     */
    public String sensitiveTypeId() {
        return this.sensitiveTypeId;
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

    public static Builder builder(GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionItemDimension defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String sensitiveDataModelId;
        private String sensitiveTypeId;
        private String targetId;
        public Builder() {}
        public Builder(GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionItemDimension defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.sensitiveDataModelId = defaults.sensitiveDataModelId;
    	      this.sensitiveTypeId = defaults.sensitiveTypeId;
    	      this.targetId = defaults.targetId;
        }

        @CustomType.Setter
        public Builder sensitiveDataModelId(String sensitiveDataModelId) {
            if (sensitiveDataModelId == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionItemDimension", "sensitiveDataModelId");
            }
            this.sensitiveDataModelId = sensitiveDataModelId;
            return this;
        }
        @CustomType.Setter
        public Builder sensitiveTypeId(String sensitiveTypeId) {
            if (sensitiveTypeId == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionItemDimension", "sensitiveTypeId");
            }
            this.sensitiveTypeId = sensitiveTypeId;
            return this;
        }
        @CustomType.Setter
        public Builder targetId(String targetId) {
            if (targetId == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionItemDimension", "targetId");
            }
            this.targetId = targetId;
            return this;
        }
        public GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionItemDimension build() {
            final var _resultValue = new GetDiscoveryAnalyticsDiscoveryAnalyticsCollectionItemDimension();
            _resultValue.sensitiveDataModelId = sensitiveDataModelId;
            _resultValue.sensitiveTypeId = sensitiveTypeId;
            _resultValue.targetId = targetId;
            return _resultValue;
        }
    }
}
