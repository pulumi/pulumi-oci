// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class NetworkSourceVirtualSourceList {
    private List<String> ipRanges;
    private String vcnId;

    private NetworkSourceVirtualSourceList() {}
    public List<String> ipRanges() {
        return this.ipRanges;
    }
    public String vcnId() {
        return this.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(NetworkSourceVirtualSourceList defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> ipRanges;
        private String vcnId;
        public Builder() {}
        public Builder(NetworkSourceVirtualSourceList defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ipRanges = defaults.ipRanges;
    	      this.vcnId = defaults.vcnId;
        }

        @CustomType.Setter
        public Builder ipRanges(List<String> ipRanges) {
            this.ipRanges = Objects.requireNonNull(ipRanges);
            return this;
        }
        public Builder ipRanges(String... ipRanges) {
            return ipRanges(List.of(ipRanges));
        }
        @CustomType.Setter
        public Builder vcnId(String vcnId) {
            this.vcnId = Objects.requireNonNull(vcnId);
            return this;
        }
        public NetworkSourceVirtualSourceList build() {
            final var o = new NetworkSourceVirtualSourceList();
            o.ipRanges = ipRanges;
            o.vcnId = vcnId;
            return o;
        }
    }
}