// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNetworkSourceVirtualSourceList {
    private List<String> ipRanges;
    private String vcnId;

    private GetNetworkSourceVirtualSourceList() {}
    public List<String> ipRanges() {
        return this.ipRanges;
    }
    public String vcnId() {
        return this.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkSourceVirtualSourceList defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> ipRanges;
        private String vcnId;
        public Builder() {}
        public Builder(GetNetworkSourceVirtualSourceList defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ipRanges = defaults.ipRanges;
    	      this.vcnId = defaults.vcnId;
        }

        @CustomType.Setter
        public Builder ipRanges(List<String> ipRanges) {
            if (ipRanges == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourceVirtualSourceList", "ipRanges");
            }
            this.ipRanges = ipRanges;
            return this;
        }
        public Builder ipRanges(String... ipRanges) {
            return ipRanges(List.of(ipRanges));
        }
        @CustomType.Setter
        public Builder vcnId(String vcnId) {
            if (vcnId == null) {
              throw new MissingRequiredPropertyException("GetNetworkSourceVirtualSourceList", "vcnId");
            }
            this.vcnId = vcnId;
            return this;
        }
        public GetNetworkSourceVirtualSourceList build() {
            final var _resultValue = new GetNetworkSourceVirtualSourceList();
            _resultValue.ipRanges = ipRanges;
            _resultValue.vcnId = vcnId;
            return _resultValue;
        }
    }
}
