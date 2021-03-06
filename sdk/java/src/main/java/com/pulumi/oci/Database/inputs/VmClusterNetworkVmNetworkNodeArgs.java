// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VmClusterNetworkVmNetworkNodeArgs extends com.pulumi.resources.ResourceArgs {

    public static final VmClusterNetworkVmNetworkNodeArgs Empty = new VmClusterNetworkVmNetworkNodeArgs();

    /**
     * (Updatable) The node host name.
     * 
     */
    @Import(name="hostname", required=true)
    private Output<String> hostname;

    /**
     * @return (Updatable) The node host name.
     * 
     */
    public Output<String> hostname() {
        return this.hostname;
    }

    /**
     * (Updatable) The node IP address.
     * 
     */
    @Import(name="ip", required=true)
    private Output<String> ip;

    /**
     * @return (Updatable) The node IP address.
     * 
     */
    public Output<String> ip() {
        return this.ip;
    }

    /**
     * (Updatable) The node virtual IP (VIP) address.
     * 
     */
    @Import(name="vip")
    private @Nullable Output<String> vip;

    /**
     * @return (Updatable) The node virtual IP (VIP) address.
     * 
     */
    public Optional<Output<String>> vip() {
        return Optional.ofNullable(this.vip);
    }

    /**
     * (Updatable) The node virtual IP (VIP) host name.
     * 
     */
    @Import(name="vipHostname")
    private @Nullable Output<String> vipHostname;

    /**
     * @return (Updatable) The node virtual IP (VIP) host name.
     * 
     */
    public Optional<Output<String>> vipHostname() {
        return Optional.ofNullable(this.vipHostname);
    }

    private VmClusterNetworkVmNetworkNodeArgs() {}

    private VmClusterNetworkVmNetworkNodeArgs(VmClusterNetworkVmNetworkNodeArgs $) {
        this.hostname = $.hostname;
        this.ip = $.ip;
        this.vip = $.vip;
        this.vipHostname = $.vipHostname;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VmClusterNetworkVmNetworkNodeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VmClusterNetworkVmNetworkNodeArgs $;

        public Builder() {
            $ = new VmClusterNetworkVmNetworkNodeArgs();
        }

        public Builder(VmClusterNetworkVmNetworkNodeArgs defaults) {
            $ = new VmClusterNetworkVmNetworkNodeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param hostname (Updatable) The node host name.
         * 
         * @return builder
         * 
         */
        public Builder hostname(Output<String> hostname) {
            $.hostname = hostname;
            return this;
        }

        /**
         * @param hostname (Updatable) The node host name.
         * 
         * @return builder
         * 
         */
        public Builder hostname(String hostname) {
            return hostname(Output.of(hostname));
        }

        /**
         * @param ip (Updatable) The node IP address.
         * 
         * @return builder
         * 
         */
        public Builder ip(Output<String> ip) {
            $.ip = ip;
            return this;
        }

        /**
         * @param ip (Updatable) The node IP address.
         * 
         * @return builder
         * 
         */
        public Builder ip(String ip) {
            return ip(Output.of(ip));
        }

        /**
         * @param vip (Updatable) The node virtual IP (VIP) address.
         * 
         * @return builder
         * 
         */
        public Builder vip(@Nullable Output<String> vip) {
            $.vip = vip;
            return this;
        }

        /**
         * @param vip (Updatable) The node virtual IP (VIP) address.
         * 
         * @return builder
         * 
         */
        public Builder vip(String vip) {
            return vip(Output.of(vip));
        }

        /**
         * @param vipHostname (Updatable) The node virtual IP (VIP) host name.
         * 
         * @return builder
         * 
         */
        public Builder vipHostname(@Nullable Output<String> vipHostname) {
            $.vipHostname = vipHostname;
            return this;
        }

        /**
         * @param vipHostname (Updatable) The node virtual IP (VIP) host name.
         * 
         * @return builder
         * 
         */
        public Builder vipHostname(String vipHostname) {
            return vipHostname(Output.of(vipHostname));
        }

        public VmClusterNetworkVmNetworkNodeArgs build() {
            $.hostname = Objects.requireNonNull($.hostname, "expected parameter 'hostname' to be non-null");
            $.ip = Objects.requireNonNull($.ip, "expected parameter 'ip' to be non-null");
            return $;
        }
    }

}
