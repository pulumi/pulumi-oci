// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Redis.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RedisClusterNodeCollectionItem {
    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The fully qualified domain name (FQDN) of the API endpoint to access a specific node.
     * 
     */
    private @Nullable String privateEndpointFqdn;
    /**
     * @return The private IP address of the API endpoint to access a specific node.
     * 
     */
    private @Nullable String privateEndpointIpAddress;

    private RedisClusterNodeCollectionItem() {}
    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The fully qualified domain name (FQDN) of the API endpoint to access a specific node.
     * 
     */
    public Optional<String> privateEndpointFqdn() {
        return Optional.ofNullable(this.privateEndpointFqdn);
    }
    /**
     * @return The private IP address of the API endpoint to access a specific node.
     * 
     */
    public Optional<String> privateEndpointIpAddress() {
        return Optional.ofNullable(this.privateEndpointIpAddress);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RedisClusterNodeCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private @Nullable String privateEndpointFqdn;
        private @Nullable String privateEndpointIpAddress;
        public Builder() {}
        public Builder(RedisClusterNodeCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.privateEndpointFqdn = defaults.privateEndpointFqdn;
    	      this.privateEndpointIpAddress = defaults.privateEndpointIpAddress;
        }

        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointFqdn(@Nullable String privateEndpointFqdn) {

            this.privateEndpointFqdn = privateEndpointFqdn;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpointIpAddress(@Nullable String privateEndpointIpAddress) {

            this.privateEndpointIpAddress = privateEndpointIpAddress;
            return this;
        }
        public RedisClusterNodeCollectionItem build() {
            final var _resultValue = new RedisClusterNodeCollectionItem();
            _resultValue.displayName = displayName;
            _resultValue.privateEndpointFqdn = privateEndpointFqdn;
            _resultValue.privateEndpointIpAddress = privateEndpointIpAddress;
            return _resultValue;
        }
    }
}
