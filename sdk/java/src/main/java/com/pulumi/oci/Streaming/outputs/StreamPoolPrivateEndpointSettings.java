// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Streaming.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class StreamPoolPrivateEndpointSettings {
    /**
     * @return The optional list of network security groups to be used with the private endpoint of the stream pool. That value cannot be changed.
     * 
     */
    private @Nullable List<String> nsgIds;
    /**
     * @return The optional private IP you want to be associated with your private stream pool. That parameter can only be specified when the subnetId parameter is set. It cannot be changed. The private IP needs to be part of the CIDR range of the specified subnetId or the creation will fail. If not specified a random IP inside the subnet will be chosen. After the stream pool is created, a custom FQDN, pointing to this private IP, is created. The FQDN is then used to access the service instead of the private IP.
     * 
     */
    private @Nullable String privateEndpointIp;
    /**
     * @return If specified, the stream pool will be private and only accessible from inside that subnet. Producing-to and consuming-from a stream inside a private stream pool can also only be done from inside the subnet. That value cannot be changed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private @Nullable String subnetId;

    private StreamPoolPrivateEndpointSettings() {}
    /**
     * @return The optional list of network security groups to be used with the private endpoint of the stream pool. That value cannot be changed.
     * 
     */
    public List<String> nsgIds() {
        return this.nsgIds == null ? List.of() : this.nsgIds;
    }
    /**
     * @return The optional private IP you want to be associated with your private stream pool. That parameter can only be specified when the subnetId parameter is set. It cannot be changed. The private IP needs to be part of the CIDR range of the specified subnetId or the creation will fail. If not specified a random IP inside the subnet will be chosen. After the stream pool is created, a custom FQDN, pointing to this private IP, is created. The FQDN is then used to access the service instead of the private IP.
     * 
     */
    public Optional<String> privateEndpointIp() {
        return Optional.ofNullable(this.privateEndpointIp);
    }
    /**
     * @return If specified, the stream pool will be private and only accessible from inside that subnet. Producing-to and consuming-from a stream inside a private stream pool can also only be done from inside the subnet. That value cannot be changed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<String> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(StreamPoolPrivateEndpointSettings defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> nsgIds;
        private @Nullable String privateEndpointIp;
        private @Nullable String subnetId;
        public Builder() {}
        public Builder(StreamPoolPrivateEndpointSettings defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.nsgIds = defaults.nsgIds;
    	      this.privateEndpointIp = defaults.privateEndpointIp;
    	      this.subnetId = defaults.subnetId;
        }

        @CustomType.Setter
        public Builder nsgIds(@Nullable List<String> nsgIds) {

            this.nsgIds = nsgIds;
            return this;
        }
        public Builder nsgIds(String... nsgIds) {
            return nsgIds(List.of(nsgIds));
        }
        @CustomType.Setter
        public Builder privateEndpointIp(@Nullable String privateEndpointIp) {

            this.privateEndpointIp = privateEndpointIp;
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(@Nullable String subnetId) {

            this.subnetId = subnetId;
            return this;
        }
        public StreamPoolPrivateEndpointSettings build() {
            final var _resultValue = new StreamPoolPrivateEndpointSettings();
            _resultValue.nsgIds = nsgIds;
            _resultValue.privateEndpointIp = privateEndpointIp;
            _resultValue.subnetId = subnetId;
            return _resultValue;
        }
    }
}
