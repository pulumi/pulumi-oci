// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCpeDeviceShapeCpeDeviceInfo {
    /**
     * @return The platform or software version of the CPE device.
     * 
     */
    private final String platformSoftwareVersion;
    /**
     * @return The vendor that makes the CPE device.
     * 
     */
    private final String vendor;

    @CustomType.Constructor
    private GetCpeDeviceShapeCpeDeviceInfo(
        @CustomType.Parameter("platformSoftwareVersion") String platformSoftwareVersion,
        @CustomType.Parameter("vendor") String vendor) {
        this.platformSoftwareVersion = platformSoftwareVersion;
        this.vendor = vendor;
    }

    /**
     * @return The platform or software version of the CPE device.
     * 
     */
    public String platformSoftwareVersion() {
        return this.platformSoftwareVersion;
    }
    /**
     * @return The vendor that makes the CPE device.
     * 
     */
    public String vendor() {
        return this.vendor;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCpeDeviceShapeCpeDeviceInfo defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String platformSoftwareVersion;
        private String vendor;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCpeDeviceShapeCpeDeviceInfo defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.platformSoftwareVersion = defaults.platformSoftwareVersion;
    	      this.vendor = defaults.vendor;
        }

        public Builder platformSoftwareVersion(String platformSoftwareVersion) {
            this.platformSoftwareVersion = Objects.requireNonNull(platformSoftwareVersion);
            return this;
        }
        public Builder vendor(String vendor) {
            this.vendor = Objects.requireNonNull(vendor);
            return this;
        }        public GetCpeDeviceShapeCpeDeviceInfo build() {
            return new GetCpeDeviceShapeCpeDeviceInfo(platformSoftwareVersion, vendor);
        }
    }
}
