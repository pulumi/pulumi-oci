// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAssetVmwareVcenter {
    /**
     * @return Data center name.
     * 
     */
    private String dataCenter;
    /**
     * @return vCenter unique key.
     * 
     */
    private String vcenterKey;
    /**
     * @return Dot-separated version string.
     * 
     */
    private String vcenterVersion;

    private GetAssetVmwareVcenter() {}
    /**
     * @return Data center name.
     * 
     */
    public String dataCenter() {
        return this.dataCenter;
    }
    /**
     * @return vCenter unique key.
     * 
     */
    public String vcenterKey() {
        return this.vcenterKey;
    }
    /**
     * @return Dot-separated version string.
     * 
     */
    public String vcenterVersion() {
        return this.vcenterVersion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAssetVmwareVcenter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dataCenter;
        private String vcenterKey;
        private String vcenterVersion;
        public Builder() {}
        public Builder(GetAssetVmwareVcenter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dataCenter = defaults.dataCenter;
    	      this.vcenterKey = defaults.vcenterKey;
    	      this.vcenterVersion = defaults.vcenterVersion;
        }

        @CustomType.Setter
        public Builder dataCenter(String dataCenter) {
            this.dataCenter = Objects.requireNonNull(dataCenter);
            return this;
        }
        @CustomType.Setter
        public Builder vcenterKey(String vcenterKey) {
            this.vcenterKey = Objects.requireNonNull(vcenterKey);
            return this;
        }
        @CustomType.Setter
        public Builder vcenterVersion(String vcenterVersion) {
            this.vcenterVersion = Objects.requireNonNull(vcenterVersion);
            return this;
        }
        public GetAssetVmwareVcenter build() {
            final var o = new GetAssetVmwareVcenter();
            o.dataCenter = dataCenter;
            o.vcenterKey = vcenterKey;
            o.vcenterVersion = vcenterVersion;
            return o;
        }
    }
}