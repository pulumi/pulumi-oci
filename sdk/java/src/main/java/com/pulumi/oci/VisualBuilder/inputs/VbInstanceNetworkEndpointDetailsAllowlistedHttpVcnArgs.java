// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.VisualBuilder.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs extends com.pulumi.resources.ResourceArgs {

    public static final VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs Empty = new VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs();

    /**
     * (Updatable) Source IP addresses or IP address ranges ingress rules. (ex: &#34;168.122.59.5/32&#34;, &#34;10.20.30.0/26&#34;) An invalid IP or CIDR block will result in a 400 response.
     * 
     */
    @Import(name="allowlistedIpCidrs")
    private @Nullable Output<List<String>> allowlistedIpCidrs;

    /**
     * @return (Updatable) Source IP addresses or IP address ranges ingress rules. (ex: &#34;168.122.59.5/32&#34;, &#34;10.20.30.0/26&#34;) An invalid IP or CIDR block will result in a 400 response.
     * 
     */
    public Optional<Output<List<String>>> allowlistedIpCidrs() {
        return Optional.ofNullable(this.allowlistedIpCidrs);
    }

    /**
     * (Updatable) The Virtual Cloud Network OCID.
     * 
     */
    @Import(name="id", required=true)
    private Output<String> id;

    /**
     * @return (Updatable) The Virtual Cloud Network OCID.
     * 
     */
    public Output<String> id() {
        return this.id;
    }

    private VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs() {}

    private VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs(VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs $) {
        this.allowlistedIpCidrs = $.allowlistedIpCidrs;
        this.id = $.id;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs $;

        public Builder() {
            $ = new VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs();
        }

        public Builder(VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs defaults) {
            $ = new VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param allowlistedIpCidrs (Updatable) Source IP addresses or IP address ranges ingress rules. (ex: &#34;168.122.59.5/32&#34;, &#34;10.20.30.0/26&#34;) An invalid IP or CIDR block will result in a 400 response.
         * 
         * @return builder
         * 
         */
        public Builder allowlistedIpCidrs(@Nullable Output<List<String>> allowlistedIpCidrs) {
            $.allowlistedIpCidrs = allowlistedIpCidrs;
            return this;
        }

        /**
         * @param allowlistedIpCidrs (Updatable) Source IP addresses or IP address ranges ingress rules. (ex: &#34;168.122.59.5/32&#34;, &#34;10.20.30.0/26&#34;) An invalid IP or CIDR block will result in a 400 response.
         * 
         * @return builder
         * 
         */
        public Builder allowlistedIpCidrs(List<String> allowlistedIpCidrs) {
            return allowlistedIpCidrs(Output.of(allowlistedIpCidrs));
        }

        /**
         * @param allowlistedIpCidrs (Updatable) Source IP addresses or IP address ranges ingress rules. (ex: &#34;168.122.59.5/32&#34;, &#34;10.20.30.0/26&#34;) An invalid IP or CIDR block will result in a 400 response.
         * 
         * @return builder
         * 
         */
        public Builder allowlistedIpCidrs(String... allowlistedIpCidrs) {
            return allowlistedIpCidrs(List.of(allowlistedIpCidrs));
        }

        /**
         * @param id (Updatable) The Virtual Cloud Network OCID.
         * 
         * @return builder
         * 
         */
        public Builder id(Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id (Updatable) The Virtual Cloud Network OCID.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        public VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs build() {
            if ($.id == null) {
                throw new MissingRequiredPropertyException("VbInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs", "id");
            }
            return $;
        }
    }

}
