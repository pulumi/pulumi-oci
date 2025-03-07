// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem {
    /**
     * @return The deployment category defines the broad separation of the deployment type into three categories. Currently the separation is &#39;DATA_REPLICATION&#39;, &#39;STREAM_ANALYTICS&#39; and &#39;DATA_TRANSFORMS&#39;.
     * 
     */
    private String category;
    /**
     * @return The default CPU core count.
     * 
     */
    private Integer defaultCpuCoreCount;
    /**
     * @return An object&#39;s Display Name.
     * 
     */
    private String displayName;
    /**
     * @return Specifies whether the deployment is used in a production or development/testing environment.
     * 
     */
    private String environmentType;
    /**
     * @return Specifies whether the &#34;Auto scaling&#34; option should be enabled by default or not.
     * 
     */
    private Boolean isAutoScalingEnabledByDefault;
    /**
     * @return The maximum CPU core count.
     * 
     */
    private Integer maxCpuCoreCount;
    /**
     * @return The multiplier value between CPU core count and memory size.
     * 
     */
    private Integer memoryPerOcpuInGbs;
    /**
     * @return The minimum CPU core count.
     * 
     */
    private Integer minCpuCoreCount;
    /**
     * @return The multiplier value between CPU core count and network bandwidth.
     * 
     */
    private Integer networkBandwidthPerOcpuInGbps;
    /**
     * @return The multiplier value between CPU core count and storage usage limit size.
     * 
     */
    private Integer storageUsageLimitPerOcpuInGbs;

    private GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem() {}
    /**
     * @return The deployment category defines the broad separation of the deployment type into three categories. Currently the separation is &#39;DATA_REPLICATION&#39;, &#39;STREAM_ANALYTICS&#39; and &#39;DATA_TRANSFORMS&#39;.
     * 
     */
    public String category() {
        return this.category;
    }
    /**
     * @return The default CPU core count.
     * 
     */
    public Integer defaultCpuCoreCount() {
        return this.defaultCpuCoreCount;
    }
    /**
     * @return An object&#39;s Display Name.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Specifies whether the deployment is used in a production or development/testing environment.
     * 
     */
    public String environmentType() {
        return this.environmentType;
    }
    /**
     * @return Specifies whether the &#34;Auto scaling&#34; option should be enabled by default or not.
     * 
     */
    public Boolean isAutoScalingEnabledByDefault() {
        return this.isAutoScalingEnabledByDefault;
    }
    /**
     * @return The maximum CPU core count.
     * 
     */
    public Integer maxCpuCoreCount() {
        return this.maxCpuCoreCount;
    }
    /**
     * @return The multiplier value between CPU core count and memory size.
     * 
     */
    public Integer memoryPerOcpuInGbs() {
        return this.memoryPerOcpuInGbs;
    }
    /**
     * @return The minimum CPU core count.
     * 
     */
    public Integer minCpuCoreCount() {
        return this.minCpuCoreCount;
    }
    /**
     * @return The multiplier value between CPU core count and network bandwidth.
     * 
     */
    public Integer networkBandwidthPerOcpuInGbps() {
        return this.networkBandwidthPerOcpuInGbps;
    }
    /**
     * @return The multiplier value between CPU core count and storage usage limit size.
     * 
     */
    public Integer storageUsageLimitPerOcpuInGbs() {
        return this.storageUsageLimitPerOcpuInGbs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String category;
        private Integer defaultCpuCoreCount;
        private String displayName;
        private String environmentType;
        private Boolean isAutoScalingEnabledByDefault;
        private Integer maxCpuCoreCount;
        private Integer memoryPerOcpuInGbs;
        private Integer minCpuCoreCount;
        private Integer networkBandwidthPerOcpuInGbps;
        private Integer storageUsageLimitPerOcpuInGbs;
        public Builder() {}
        public Builder(GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.category = defaults.category;
    	      this.defaultCpuCoreCount = defaults.defaultCpuCoreCount;
    	      this.displayName = defaults.displayName;
    	      this.environmentType = defaults.environmentType;
    	      this.isAutoScalingEnabledByDefault = defaults.isAutoScalingEnabledByDefault;
    	      this.maxCpuCoreCount = defaults.maxCpuCoreCount;
    	      this.memoryPerOcpuInGbs = defaults.memoryPerOcpuInGbs;
    	      this.minCpuCoreCount = defaults.minCpuCoreCount;
    	      this.networkBandwidthPerOcpuInGbps = defaults.networkBandwidthPerOcpuInGbps;
    	      this.storageUsageLimitPerOcpuInGbs = defaults.storageUsageLimitPerOcpuInGbs;
        }

        @CustomType.Setter
        public Builder category(String category) {
            if (category == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "category");
            }
            this.category = category;
            return this;
        }
        @CustomType.Setter
        public Builder defaultCpuCoreCount(Integer defaultCpuCoreCount) {
            if (defaultCpuCoreCount == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "defaultCpuCoreCount");
            }
            this.defaultCpuCoreCount = defaultCpuCoreCount;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder environmentType(String environmentType) {
            if (environmentType == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "environmentType");
            }
            this.environmentType = environmentType;
            return this;
        }
        @CustomType.Setter
        public Builder isAutoScalingEnabledByDefault(Boolean isAutoScalingEnabledByDefault) {
            if (isAutoScalingEnabledByDefault == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "isAutoScalingEnabledByDefault");
            }
            this.isAutoScalingEnabledByDefault = isAutoScalingEnabledByDefault;
            return this;
        }
        @CustomType.Setter
        public Builder maxCpuCoreCount(Integer maxCpuCoreCount) {
            if (maxCpuCoreCount == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "maxCpuCoreCount");
            }
            this.maxCpuCoreCount = maxCpuCoreCount;
            return this;
        }
        @CustomType.Setter
        public Builder memoryPerOcpuInGbs(Integer memoryPerOcpuInGbs) {
            if (memoryPerOcpuInGbs == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "memoryPerOcpuInGbs");
            }
            this.memoryPerOcpuInGbs = memoryPerOcpuInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder minCpuCoreCount(Integer minCpuCoreCount) {
            if (minCpuCoreCount == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "minCpuCoreCount");
            }
            this.minCpuCoreCount = minCpuCoreCount;
            return this;
        }
        @CustomType.Setter
        public Builder networkBandwidthPerOcpuInGbps(Integer networkBandwidthPerOcpuInGbps) {
            if (networkBandwidthPerOcpuInGbps == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "networkBandwidthPerOcpuInGbps");
            }
            this.networkBandwidthPerOcpuInGbps = networkBandwidthPerOcpuInGbps;
            return this;
        }
        @CustomType.Setter
        public Builder storageUsageLimitPerOcpuInGbs(Integer storageUsageLimitPerOcpuInGbs) {
            if (storageUsageLimitPerOcpuInGbs == null) {
              throw new MissingRequiredPropertyException("GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem", "storageUsageLimitPerOcpuInGbs");
            }
            this.storageUsageLimitPerOcpuInGbs = storageUsageLimitPerOcpuInGbs;
            return this;
        }
        public GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem build() {
            final var _resultValue = new GetDeploymentEnvironmentsDeploymentEnvironmentCollectionItem();
            _resultValue.category = category;
            _resultValue.defaultCpuCoreCount = defaultCpuCoreCount;
            _resultValue.displayName = displayName;
            _resultValue.environmentType = environmentType;
            _resultValue.isAutoScalingEnabledByDefault = isAutoScalingEnabledByDefault;
            _resultValue.maxCpuCoreCount = maxCpuCoreCount;
            _resultValue.memoryPerOcpuInGbs = memoryPerOcpuInGbs;
            _resultValue.minCpuCoreCount = minCpuCoreCount;
            _resultValue.networkBandwidthPerOcpuInGbps = networkBandwidthPerOcpuInGbps;
            _resultValue.storageUsageLimitPerOcpuInGbs = storageUsageLimitPerOcpuInGbs;
            return _resultValue;
        }
    }
}
