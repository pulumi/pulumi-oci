// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAssetsAssetCollectionItemVm {
    /**
     * @return Host name/IP address of VM on which the host is running.
     * 
     */
    private String hypervisorHost;
    /**
     * @return Hypervisor vendor.
     * 
     */
    private String hypervisorVendor;
    /**
     * @return Hypervisor version.
     * 
     */
    private String hypervisorVersion;

    private GetAssetsAssetCollectionItemVm() {}
    /**
     * @return Host name/IP address of VM on which the host is running.
     * 
     */
    public String hypervisorHost() {
        return this.hypervisorHost;
    }
    /**
     * @return Hypervisor vendor.
     * 
     */
    public String hypervisorVendor() {
        return this.hypervisorVendor;
    }
    /**
     * @return Hypervisor version.
     * 
     */
    public String hypervisorVersion() {
        return this.hypervisorVersion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAssetsAssetCollectionItemVm defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hypervisorHost;
        private String hypervisorVendor;
        private String hypervisorVersion;
        public Builder() {}
        public Builder(GetAssetsAssetCollectionItemVm defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hypervisorHost = defaults.hypervisorHost;
    	      this.hypervisorVendor = defaults.hypervisorVendor;
    	      this.hypervisorVersion = defaults.hypervisorVersion;
        }

        @CustomType.Setter
        public Builder hypervisorHost(String hypervisorHost) {
            if (hypervisorHost == null) {
              throw new MissingRequiredPropertyException("GetAssetsAssetCollectionItemVm", "hypervisorHost");
            }
            this.hypervisorHost = hypervisorHost;
            return this;
        }
        @CustomType.Setter
        public Builder hypervisorVendor(String hypervisorVendor) {
            if (hypervisorVendor == null) {
              throw new MissingRequiredPropertyException("GetAssetsAssetCollectionItemVm", "hypervisorVendor");
            }
            this.hypervisorVendor = hypervisorVendor;
            return this;
        }
        @CustomType.Setter
        public Builder hypervisorVersion(String hypervisorVersion) {
            if (hypervisorVersion == null) {
              throw new MissingRequiredPropertyException("GetAssetsAssetCollectionItemVm", "hypervisorVersion");
            }
            this.hypervisorVersion = hypervisorVersion;
            return this;
        }
        public GetAssetsAssetCollectionItemVm build() {
            final var _resultValue = new GetAssetsAssetCollectionItemVm();
            _resultValue.hypervisorHost = hypervisorHost;
            _resultValue.hypervisorVendor = hypervisorVendor;
            _resultValue.hypervisorVersion = hypervisorVersion;
            return _resultValue;
        }
    }
}
