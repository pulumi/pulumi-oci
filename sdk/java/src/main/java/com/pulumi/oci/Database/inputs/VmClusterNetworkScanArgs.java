// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class VmClusterNetworkScanArgs extends com.pulumi.resources.ResourceArgs {

    public static final VmClusterNetworkScanArgs Empty = new VmClusterNetworkScanArgs();

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
     * (Updatable) The list of SCAN IP addresses. Three addresses should be provided.
     * 
     */
    @Import(name="ips", required=true)
    private Output<List<String>> ips;

    /**
     * @return (Updatable) The list of SCAN IP addresses. Three addresses should be provided.
     * 
     */
    public Output<List<String>> ips() {
        return this.ips;
    }

    /**
     * (Updatable) The SCAN TCPIP port. Default is 1521.
     * 
     */
    @Import(name="port", required=true)
    private Output<Integer> port;

    /**
     * @return (Updatable) The SCAN TCPIP port. Default is 1521.
     * 
     */
    public Output<Integer> port() {
        return this.port;
    }

    /**
     * (Updatable) The SCAN TCPIP port. Default is 1521.
     * 
     */
    @Import(name="scanListenerPortTcp")
    private @Nullable Output<Integer> scanListenerPortTcp;

    /**
     * @return (Updatable) The SCAN TCPIP port. Default is 1521.
     * 
     */
    public Optional<Output<Integer>> scanListenerPortTcp() {
        return Optional.ofNullable(this.scanListenerPortTcp);
    }

    /**
     * (Updatable) The SCAN TCPIP SSL port. Default is 2484.
     * 
     */
    @Import(name="scanListenerPortTcpSsl")
    private @Nullable Output<Integer> scanListenerPortTcpSsl;

    /**
     * @return (Updatable) The SCAN TCPIP SSL port. Default is 2484.
     * 
     */
    public Optional<Output<Integer>> scanListenerPortTcpSsl() {
        return Optional.ofNullable(this.scanListenerPortTcpSsl);
    }

    private VmClusterNetworkScanArgs() {}

    private VmClusterNetworkScanArgs(VmClusterNetworkScanArgs $) {
        this.hostname = $.hostname;
        this.ips = $.ips;
        this.port = $.port;
        this.scanListenerPortTcp = $.scanListenerPortTcp;
        this.scanListenerPortTcpSsl = $.scanListenerPortTcpSsl;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VmClusterNetworkScanArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VmClusterNetworkScanArgs $;

        public Builder() {
            $ = new VmClusterNetworkScanArgs();
        }

        public Builder(VmClusterNetworkScanArgs defaults) {
            $ = new VmClusterNetworkScanArgs(Objects.requireNonNull(defaults));
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
         * @param ips (Updatable) The list of SCAN IP addresses. Three addresses should be provided.
         * 
         * @return builder
         * 
         */
        public Builder ips(Output<List<String>> ips) {
            $.ips = ips;
            return this;
        }

        /**
         * @param ips (Updatable) The list of SCAN IP addresses. Three addresses should be provided.
         * 
         * @return builder
         * 
         */
        public Builder ips(List<String> ips) {
            return ips(Output.of(ips));
        }

        /**
         * @param ips (Updatable) The list of SCAN IP addresses. Three addresses should be provided.
         * 
         * @return builder
         * 
         */
        public Builder ips(String... ips) {
            return ips(List.of(ips));
        }

        /**
         * @param port (Updatable) The SCAN TCPIP port. Default is 1521.
         * 
         * @return builder
         * 
         */
        public Builder port(Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port (Updatable) The SCAN TCPIP port. Default is 1521.
         * 
         * @return builder
         * 
         */
        public Builder port(Integer port) {
            return port(Output.of(port));
        }

        /**
         * @param scanListenerPortTcp (Updatable) The SCAN TCPIP port. Default is 1521.
         * 
         * @return builder
         * 
         */
        public Builder scanListenerPortTcp(@Nullable Output<Integer> scanListenerPortTcp) {
            $.scanListenerPortTcp = scanListenerPortTcp;
            return this;
        }

        /**
         * @param scanListenerPortTcp (Updatable) The SCAN TCPIP port. Default is 1521.
         * 
         * @return builder
         * 
         */
        public Builder scanListenerPortTcp(Integer scanListenerPortTcp) {
            return scanListenerPortTcp(Output.of(scanListenerPortTcp));
        }

        /**
         * @param scanListenerPortTcpSsl (Updatable) The SCAN TCPIP SSL port. Default is 2484.
         * 
         * @return builder
         * 
         */
        public Builder scanListenerPortTcpSsl(@Nullable Output<Integer> scanListenerPortTcpSsl) {
            $.scanListenerPortTcpSsl = scanListenerPortTcpSsl;
            return this;
        }

        /**
         * @param scanListenerPortTcpSsl (Updatable) The SCAN TCPIP SSL port. Default is 2484.
         * 
         * @return builder
         * 
         */
        public Builder scanListenerPortTcpSsl(Integer scanListenerPortTcpSsl) {
            return scanListenerPortTcpSsl(Output.of(scanListenerPortTcpSsl));
        }

        public VmClusterNetworkScanArgs build() {
            $.hostname = Objects.requireNonNull($.hostname, "expected parameter 'hostname' to be non-null");
            $.ips = Objects.requireNonNull($.ips, "expected parameter 'ips' to be non-null");
            $.port = Objects.requireNonNull($.port, "expected parameter 'port' to be non-null");
            return $;
        }
    }

}