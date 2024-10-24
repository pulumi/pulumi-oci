// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkLoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkLoadBalancer.outputs.GetNetworkLoadBalancerIpAddressReservedIp;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkLoadBalancerIpAddress {
    /**
     * @return An IP address.  Example: `192.168.0.3`
     * 
     */
    private String ipAddress;
    /**
     * @return IP version associated with the listener.
     * 
     */
    private String ipVersion;
    /**
     * @return Whether the IP address is public or private.
     * 
     */
    private Boolean isPublic;
    /**
     * @return An object representing a reserved IP address to be attached or that is already attached to a network load balancer.
     * 
     */
    private List<GetNetworkLoadBalancerIpAddressReservedIp> reservedIps;

    private GetNetworkLoadBalancerIpAddress() {}
    /**
     * @return An IP address.  Example: `192.168.0.3`
     * 
     */
    public String ipAddress() {
        return this.ipAddress;
    }
    /**
     * @return IP version associated with the listener.
     * 
     */
    public String ipVersion() {
        return this.ipVersion;
    }
    /**
     * @return Whether the IP address is public or private.
     * 
     */
    public Boolean isPublic() {
        return this.isPublic;
    }
    /**
     * @return An object representing a reserved IP address to be attached or that is already attached to a network load balancer.
     * 
     */
    public List<GetNetworkLoadBalancerIpAddressReservedIp> reservedIps() {
        return this.reservedIps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkLoadBalancerIpAddress defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ipAddress;
        private String ipVersion;
        private Boolean isPublic;
        private List<GetNetworkLoadBalancerIpAddressReservedIp> reservedIps;
        public Builder() {}
        public Builder(GetNetworkLoadBalancerIpAddress defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ipAddress = defaults.ipAddress;
    	      this.ipVersion = defaults.ipVersion;
    	      this.isPublic = defaults.isPublic;
    	      this.reservedIps = defaults.reservedIps;
        }

        @CustomType.Setter
        public Builder ipAddress(String ipAddress) {
            if (ipAddress == null) {
              throw new MissingRequiredPropertyException("GetNetworkLoadBalancerIpAddress", "ipAddress");
            }
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder ipVersion(String ipVersion) {
            if (ipVersion == null) {
              throw new MissingRequiredPropertyException("GetNetworkLoadBalancerIpAddress", "ipVersion");
            }
            this.ipVersion = ipVersion;
            return this;
        }
        @CustomType.Setter
        public Builder isPublic(Boolean isPublic) {
            if (isPublic == null) {
              throw new MissingRequiredPropertyException("GetNetworkLoadBalancerIpAddress", "isPublic");
            }
            this.isPublic = isPublic;
            return this;
        }
        @CustomType.Setter
        public Builder reservedIps(List<GetNetworkLoadBalancerIpAddressReservedIp> reservedIps) {
            if (reservedIps == null) {
              throw new MissingRequiredPropertyException("GetNetworkLoadBalancerIpAddress", "reservedIps");
            }
            this.reservedIps = reservedIps;
            return this;
        }
        public Builder reservedIps(GetNetworkLoadBalancerIpAddressReservedIp... reservedIps) {
            return reservedIps(List.of(reservedIps));
        }
        public GetNetworkLoadBalancerIpAddress build() {
            final var _resultValue = new GetNetworkLoadBalancerIpAddress();
            _resultValue.ipAddress = ipAddress;
            _resultValue.ipVersion = ipVersion;
            _resultValue.isPublic = isPublic;
            _resultValue.reservedIps = reservedIps;
            return _resultValue;
        }
    }
}
