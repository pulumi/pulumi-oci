// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetail {
    private @Nullable String ipv6address;
    private @Nullable String ipv6subnetCidr;

    private InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetail() {}
    public Optional<String> ipv6address() {
        return Optional.ofNullable(this.ipv6address);
    }
    public Optional<String> ipv6subnetCidr() {
        return Optional.ofNullable(this.ipv6subnetCidr);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String ipv6address;
        private @Nullable String ipv6subnetCidr;
        public Builder() {}
        public Builder(InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ipv6address = defaults.ipv6address;
    	      this.ipv6subnetCidr = defaults.ipv6subnetCidr;
        }

        @CustomType.Setter
        public Builder ipv6address(@Nullable String ipv6address) {
            this.ipv6address = ipv6address;
            return this;
        }
        @CustomType.Setter
        public Builder ipv6subnetCidr(@Nullable String ipv6subnetCidr) {
            this.ipv6subnetCidr = ipv6subnetCidr;
            return this;
        }
        public InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetail build() {
            final var o = new InstanceCreateVnicDetailsIpv6addressIpv6subnetCidrPairDetail();
            o.ipv6address = ipv6address;
            o.ipv6subnetCidr = ipv6subnetCidr;
            return o;
        }
    }
}