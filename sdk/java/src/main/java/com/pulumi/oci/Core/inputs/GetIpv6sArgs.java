// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetIpv6sFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetIpv6sArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetIpv6sArgs Empty = new GetIpv6sArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetIpv6sFilterArgs>> filters;

    public Optional<Output<List<GetIpv6sFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * An IP address. This could be either IPv4 or IPv6, depending on the resource. Example: `10.0.3.3`
     * 
     */
    @Import(name="ipAddress")
    private @Nullable Output<String> ipAddress;

    /**
     * @return An IP address. This could be either IPv4 or IPv6, depending on the resource. Example: `10.0.3.3`
     * 
     */
    public Optional<Output<String>> ipAddress() {
        return Optional.ofNullable(this.ipAddress);
    }

    /**
     * The OCID of the subnet.
     * 
     */
    @Import(name="subnetId")
    private @Nullable Output<String> subnetId;

    /**
     * @return The OCID of the subnet.
     * 
     */
    public Optional<Output<String>> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    /**
     * The OCID of the VNIC.
     * 
     */
    @Import(name="vnicId")
    private @Nullable Output<String> vnicId;

    /**
     * @return The OCID of the VNIC.
     * 
     */
    public Optional<Output<String>> vnicId() {
        return Optional.ofNullable(this.vnicId);
    }

    private GetIpv6sArgs() {}

    private GetIpv6sArgs(GetIpv6sArgs $) {
        this.filters = $.filters;
        this.ipAddress = $.ipAddress;
        this.subnetId = $.subnetId;
        this.vnicId = $.vnicId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetIpv6sArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetIpv6sArgs $;

        public Builder() {
            $ = new GetIpv6sArgs();
        }

        public Builder(GetIpv6sArgs defaults) {
            $ = new GetIpv6sArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetIpv6sFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetIpv6sFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetIpv6sFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param ipAddress An IP address. This could be either IPv4 or IPv6, depending on the resource. Example: `10.0.3.3`
         * 
         * @return builder
         * 
         */
        public Builder ipAddress(@Nullable Output<String> ipAddress) {
            $.ipAddress = ipAddress;
            return this;
        }

        /**
         * @param ipAddress An IP address. This could be either IPv4 or IPv6, depending on the resource. Example: `10.0.3.3`
         * 
         * @return builder
         * 
         */
        public Builder ipAddress(String ipAddress) {
            return ipAddress(Output.of(ipAddress));
        }

        /**
         * @param subnetId The OCID of the subnet.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(@Nullable Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The OCID of the subnet.
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        /**
         * @param vnicId The OCID of the VNIC.
         * 
         * @return builder
         * 
         */
        public Builder vnicId(@Nullable Output<String> vnicId) {
            $.vnicId = vnicId;
            return this;
        }

        /**
         * @param vnicId The OCID of the VNIC.
         * 
         * @return builder
         * 
         */
        public Builder vnicId(String vnicId) {
            return vnicId(Output.of(vnicId));
        }

        public GetIpv6sArgs build() {
            return $;
        }
    }

}
