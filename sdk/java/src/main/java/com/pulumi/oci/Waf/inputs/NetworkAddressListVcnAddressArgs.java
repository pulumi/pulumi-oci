// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waf.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkAddressListVcnAddressArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkAddressListVcnAddressArgs Empty = new NetworkAddressListVcnAddressArgs();

    /**
     * (Updatable) A private IP address or CIDR IP address range.
     * 
     */
    @Import(name="addresses")
    private @Nullable Output<String> addresses;

    /**
     * @return (Updatable) A private IP address or CIDR IP address range.
     * 
     */
    public Optional<Output<String>> addresses() {
        return Optional.ofNullable(this.addresses);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    @Import(name="vcnId")
    private @Nullable Output<String> vcnId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
     * 
     */
    public Optional<Output<String>> vcnId() {
        return Optional.ofNullable(this.vcnId);
    }

    private NetworkAddressListVcnAddressArgs() {}

    private NetworkAddressListVcnAddressArgs(NetworkAddressListVcnAddressArgs $) {
        this.addresses = $.addresses;
        this.vcnId = $.vcnId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkAddressListVcnAddressArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkAddressListVcnAddressArgs $;

        public Builder() {
            $ = new NetworkAddressListVcnAddressArgs();
        }

        public Builder(NetworkAddressListVcnAddressArgs defaults) {
            $ = new NetworkAddressListVcnAddressArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param addresses (Updatable) A private IP address or CIDR IP address range.
         * 
         * @return builder
         * 
         */
        public Builder addresses(@Nullable Output<String> addresses) {
            $.addresses = addresses;
            return this;
        }

        /**
         * @param addresses (Updatable) A private IP address or CIDR IP address range.
         * 
         * @return builder
         * 
         */
        public Builder addresses(String addresses) {
            return addresses(Output.of(addresses));
        }

        /**
         * @param vcnId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(@Nullable Output<String> vcnId) {
            $.vcnId = vcnId;
            return this;
        }

        /**
         * @param vcnId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
         * 
         * @return builder
         * 
         */
        public Builder vcnId(String vcnId) {
            return vcnId(Output.of(vcnId));
        }

        public NetworkAddressListVcnAddressArgs build() {
            return $;
        }
    }

}