// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ClusterOptionsKubernetesNetworkConfig {
    /**
     * @return The CIDR block for Kubernetes pods. Optional, defaults to 10.244.0.0/16.
     * 
     */
    private final @Nullable String podsCidr;
    /**
     * @return The CIDR block for Kubernetes services. Optional, defaults to 10.96.0.0/16.
     * 
     */
    private final @Nullable String servicesCidr;

    @CustomType.Constructor
    private ClusterOptionsKubernetesNetworkConfig(
        @CustomType.Parameter("podsCidr") @Nullable String podsCidr,
        @CustomType.Parameter("servicesCidr") @Nullable String servicesCidr) {
        this.podsCidr = podsCidr;
        this.servicesCidr = servicesCidr;
    }

    /**
     * @return The CIDR block for Kubernetes pods. Optional, defaults to 10.244.0.0/16.
     * 
     */
    public Optional<String> podsCidr() {
        return Optional.ofNullable(this.podsCidr);
    }
    /**
     * @return The CIDR block for Kubernetes services. Optional, defaults to 10.96.0.0/16.
     * 
     */
    public Optional<String> servicesCidr() {
        return Optional.ofNullable(this.servicesCidr);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ClusterOptionsKubernetesNetworkConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String podsCidr;
        private @Nullable String servicesCidr;

        public Builder() {
    	      // Empty
        }

        public Builder(ClusterOptionsKubernetesNetworkConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.podsCidr = defaults.podsCidr;
    	      this.servicesCidr = defaults.servicesCidr;
        }

        public Builder podsCidr(@Nullable String podsCidr) {
            this.podsCidr = podsCidr;
            return this;
        }
        public Builder servicesCidr(@Nullable String servicesCidr) {
            this.servicesCidr = servicesCidr;
            return this;
        }        public ClusterOptionsKubernetesNetworkConfig build() {
            return new ClusterOptionsKubernetesNetworkConfig(podsCidr, servicesCidr);
        }
    }
}
