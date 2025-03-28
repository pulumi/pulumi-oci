// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ResourceManager.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPrivateEndpointReachableIpResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return An IP address for the Resource Manager service to use for connection to the private resource.
     * 
     */
    private String ipAddress;
    private String privateEndpointId;
    private String privateIp;

    private GetPrivateEndpointReachableIpResult() {}
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return An IP address for the Resource Manager service to use for connection to the private resource.
     * 
     */
    public String ipAddress() {
        return this.ipAddress;
    }
    public String privateEndpointId() {
        return this.privateEndpointId;
    }
    public String privateIp() {
        return this.privateIp;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPrivateEndpointReachableIpResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private String ipAddress;
        private String privateEndpointId;
        private String privateIp;
        public Builder() {}
        public Builder(GetPrivateEndpointReachableIpResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.ipAddress = defaults.ipAddress;
    	      this.privateEndpointId = defaults.privateEndpointId;
    	      this.privateIp = defaults.privateIp;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointReachableIpResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ipAddress(String ipAddress) {
            if (ipAddress == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointReachableIpResult", "ipAddress");
            }
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointId(String privateEndpointId) {
            if (privateEndpointId == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointReachableIpResult", "privateEndpointId");
            }
            this.privateEndpointId = privateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder privateIp(String privateIp) {
            if (privateIp == null) {
              throw new MissingRequiredPropertyException("GetPrivateEndpointReachableIpResult", "privateIp");
            }
            this.privateIp = privateIp;
            return this;
        }
        public GetPrivateEndpointReachableIpResult build() {
            final var _resultValue = new GetPrivateEndpointReachableIpResult();
            _resultValue.id = id;
            _resultValue.ipAddress = ipAddress;
            _resultValue.privateEndpointId = privateEndpointId;
            _resultValue.privateIp = privateIp;
            return _resultValue;
        }
    }
}
