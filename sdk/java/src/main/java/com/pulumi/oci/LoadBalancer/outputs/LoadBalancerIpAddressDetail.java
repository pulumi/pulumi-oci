// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LoadBalancer.outputs.LoadBalancerIpAddressDetailReservedIp;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class LoadBalancerIpAddressDetail {
    /**
     * @return An IP address.  Example: `192.168.0.3`
     * 
     */
    private @Nullable String ipAddress;
    /**
     * @return Whether the IP address is public or private.
     * 
     */
    private @Nullable Boolean isPublic;
    private @Nullable List<LoadBalancerIpAddressDetailReservedIp> reservedIps;

    private LoadBalancerIpAddressDetail() {}
    /**
     * @return An IP address.  Example: `192.168.0.3`
     * 
     */
    public Optional<String> ipAddress() {
        return Optional.ofNullable(this.ipAddress);
    }
    /**
     * @return Whether the IP address is public or private.
     * 
     */
    public Optional<Boolean> isPublic() {
        return Optional.ofNullable(this.isPublic);
    }
    public List<LoadBalancerIpAddressDetailReservedIp> reservedIps() {
        return this.reservedIps == null ? List.of() : this.reservedIps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(LoadBalancerIpAddressDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String ipAddress;
        private @Nullable Boolean isPublic;
        private @Nullable List<LoadBalancerIpAddressDetailReservedIp> reservedIps;
        public Builder() {}
        public Builder(LoadBalancerIpAddressDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ipAddress = defaults.ipAddress;
    	      this.isPublic = defaults.isPublic;
    	      this.reservedIps = defaults.reservedIps;
        }

        @CustomType.Setter
        public Builder ipAddress(@Nullable String ipAddress) {

            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder isPublic(@Nullable Boolean isPublic) {

            this.isPublic = isPublic;
            return this;
        }
        @CustomType.Setter
        public Builder reservedIps(@Nullable List<LoadBalancerIpAddressDetailReservedIp> reservedIps) {

            this.reservedIps = reservedIps;
            return this;
        }
        public Builder reservedIps(LoadBalancerIpAddressDetailReservedIp... reservedIps) {
            return reservedIps(List.of(reservedIps));
        }
        public LoadBalancerIpAddressDetail build() {
            final var _resultValue = new LoadBalancerIpAddressDetail();
            _resultValue.ipAddress = ipAddress;
            _resultValue.isPublic = isPublic;
            _resultValue.reservedIps = reservedIps;
            return _resultValue;
        }
    }
}
