// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ClusterEndpoint {
    /**
     * @return The non-native networking Kubernetes API server endpoint.
     * 
     */
    private @Nullable String kubernetes;
    /**
     * @return The private native networking Kubernetes API server endpoint.
     * 
     */
    private @Nullable String privateEndpoint;
    /**
     * @return The public native networking Kubernetes API server endpoint, if one was requested.
     * 
     */
    private @Nullable String publicEndpoint;
    /**
     * @return The FQDN assigned to the Kubernetes API private endpoint. Example: &#39;https://yourVcnHostnameEndpoint&#39;
     * 
     */
    private @Nullable String vcnHostnameEndpoint;

    private ClusterEndpoint() {}
    /**
     * @return The non-native networking Kubernetes API server endpoint.
     * 
     */
    public Optional<String> kubernetes() {
        return Optional.ofNullable(this.kubernetes);
    }
    /**
     * @return The private native networking Kubernetes API server endpoint.
     * 
     */
    public Optional<String> privateEndpoint() {
        return Optional.ofNullable(this.privateEndpoint);
    }
    /**
     * @return The public native networking Kubernetes API server endpoint, if one was requested.
     * 
     */
    public Optional<String> publicEndpoint() {
        return Optional.ofNullable(this.publicEndpoint);
    }
    /**
     * @return The FQDN assigned to the Kubernetes API private endpoint. Example: &#39;https://yourVcnHostnameEndpoint&#39;
     * 
     */
    public Optional<String> vcnHostnameEndpoint() {
        return Optional.ofNullable(this.vcnHostnameEndpoint);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ClusterEndpoint defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String kubernetes;
        private @Nullable String privateEndpoint;
        private @Nullable String publicEndpoint;
        private @Nullable String vcnHostnameEndpoint;
        public Builder() {}
        public Builder(ClusterEndpoint defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.kubernetes = defaults.kubernetes;
    	      this.privateEndpoint = defaults.privateEndpoint;
    	      this.publicEndpoint = defaults.publicEndpoint;
    	      this.vcnHostnameEndpoint = defaults.vcnHostnameEndpoint;
        }

        @CustomType.Setter
        public Builder kubernetes(@Nullable String kubernetes) {

            this.kubernetes = kubernetes;
            return this;
        }
        @CustomType.Setter
        public Builder privateEndpoint(@Nullable String privateEndpoint) {

            this.privateEndpoint = privateEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder publicEndpoint(@Nullable String publicEndpoint) {

            this.publicEndpoint = publicEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder vcnHostnameEndpoint(@Nullable String vcnHostnameEndpoint) {

            this.vcnHostnameEndpoint = vcnHostnameEndpoint;
            return this;
        }
        public ClusterEndpoint build() {
            final var _resultValue = new ClusterEndpoint();
            _resultValue.kubernetes = kubernetes;
            _resultValue.privateEndpoint = privateEndpoint;
            _resultValue.publicEndpoint = publicEndpoint;
            _resultValue.vcnHostnameEndpoint = vcnHostnameEndpoint;
            return _resultValue;
        }
    }
}
