// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetIpv6sFilter;
import com.pulumi.oci.Core.outputs.GetIpv6sIpv6;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetIpv6sResult {
    private @Nullable List<GetIpv6sFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The IPv6 address of the `IPv6` object. The address is within the IPv6 CIDR block of the VNIC&#39;s subnet (see the `ipv6CidrBlock` attribute for the [Subnet](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Subnet/) object.  Example: `2001:0db8:0123:1111:abcd:ef01:2345:6789`
     * 
     */
    private @Nullable String ipAddress;
    /**
     * @return The list of ipv6s.
     * 
     */
    private List<GetIpv6sIpv6> ipv6s;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the VNIC is in.
     * 
     */
    private @Nullable String subnetId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC the IPv6 is assigned to. The VNIC and IPv6 must be in the same subnet.
     * 
     */
    private @Nullable String vnicId;

    private GetIpv6sResult() {}
    public List<GetIpv6sFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The IPv6 address of the `IPv6` object. The address is within the IPv6 CIDR block of the VNIC&#39;s subnet (see the `ipv6CidrBlock` attribute for the [Subnet](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Subnet/) object.  Example: `2001:0db8:0123:1111:abcd:ef01:2345:6789`
     * 
     */
    public Optional<String> ipAddress() {
        return Optional.ofNullable(this.ipAddress);
    }
    /**
     * @return The list of ipv6s.
     * 
     */
    public List<GetIpv6sIpv6> ipv6s() {
        return this.ipv6s;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the VNIC is in.
     * 
     */
    public Optional<String> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC the IPv6 is assigned to. The VNIC and IPv6 must be in the same subnet.
     * 
     */
    public Optional<String> vnicId() {
        return Optional.ofNullable(this.vnicId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpv6sResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetIpv6sFilter> filters;
        private String id;
        private @Nullable String ipAddress;
        private List<GetIpv6sIpv6> ipv6s;
        private @Nullable String subnetId;
        private @Nullable String vnicId;
        public Builder() {}
        public Builder(GetIpv6sResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.ipAddress = defaults.ipAddress;
    	      this.ipv6s = defaults.ipv6s;
    	      this.subnetId = defaults.subnetId;
    	      this.vnicId = defaults.vnicId;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetIpv6sFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetIpv6sFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder ipAddress(@Nullable String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder ipv6s(List<GetIpv6sIpv6> ipv6s) {
            this.ipv6s = Objects.requireNonNull(ipv6s);
            return this;
        }
        public Builder ipv6s(GetIpv6sIpv6... ipv6s) {
            return ipv6s(List.of(ipv6s));
        }
        @CustomType.Setter
        public Builder subnetId(@Nullable String subnetId) {
            this.subnetId = subnetId;
            return this;
        }
        @CustomType.Setter
        public Builder vnicId(@Nullable String vnicId) {
            this.vnicId = vnicId;
            return this;
        }
        public GetIpv6sResult build() {
            final var o = new GetIpv6sResult();
            o.filters = filters;
            o.id = id;
            o.ipAddress = ipAddress;
            o.ipv6s = ipv6s;
            o.subnetId = subnetId;
            o.vnicId = vnicId;
            return o;
        }
    }
}