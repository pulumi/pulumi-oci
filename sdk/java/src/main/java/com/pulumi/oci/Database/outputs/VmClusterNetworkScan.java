// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class VmClusterNetworkScan {
    /**
     * @return (Updatable) The node host name.
     * 
     */
    private String hostname;
    /**
     * @return (Updatable) The list of SCAN IP addresses. Three addresses should be provided.
     * 
     */
    private List<String> ips;
    /**
     * @return (Updatable) The SCAN TCPIP port. Default is 1521.
     * 
     */
    private Integer port;
    /**
     * @return (Updatable) The SCAN TCPIP port. Default is 1521.
     * 
     */
    private @Nullable Integer scanListenerPortTcp;
    /**
     * @return (Updatable) The SCAN TCPIP SSL port. Default is 2484.
     * 
     */
    private @Nullable Integer scanListenerPortTcpSsl;

    private VmClusterNetworkScan() {}
    /**
     * @return (Updatable) The node host name.
     * 
     */
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return (Updatable) The list of SCAN IP addresses. Three addresses should be provided.
     * 
     */
    public List<String> ips() {
        return this.ips;
    }
    /**
     * @return (Updatable) The SCAN TCPIP port. Default is 1521.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return (Updatable) The SCAN TCPIP port. Default is 1521.
     * 
     */
    public Optional<Integer> scanListenerPortTcp() {
        return Optional.ofNullable(this.scanListenerPortTcp);
    }
    /**
     * @return (Updatable) The SCAN TCPIP SSL port. Default is 2484.
     * 
     */
    public Optional<Integer> scanListenerPortTcpSsl() {
        return Optional.ofNullable(this.scanListenerPortTcpSsl);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VmClusterNetworkScan defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostname;
        private List<String> ips;
        private Integer port;
        private @Nullable Integer scanListenerPortTcp;
        private @Nullable Integer scanListenerPortTcpSsl;
        public Builder() {}
        public Builder(VmClusterNetworkScan defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostname = defaults.hostname;
    	      this.ips = defaults.ips;
    	      this.port = defaults.port;
    	      this.scanListenerPortTcp = defaults.scanListenerPortTcp;
    	      this.scanListenerPortTcpSsl = defaults.scanListenerPortTcpSsl;
        }

        @CustomType.Setter
        public Builder hostname(String hostname) {
            this.hostname = Objects.requireNonNull(hostname);
            return this;
        }
        @CustomType.Setter
        public Builder ips(List<String> ips) {
            this.ips = Objects.requireNonNull(ips);
            return this;
        }
        public Builder ips(String... ips) {
            return ips(List.of(ips));
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            this.port = Objects.requireNonNull(port);
            return this;
        }
        @CustomType.Setter
        public Builder scanListenerPortTcp(@Nullable Integer scanListenerPortTcp) {
            this.scanListenerPortTcp = scanListenerPortTcp;
            return this;
        }
        @CustomType.Setter
        public Builder scanListenerPortTcpSsl(@Nullable Integer scanListenerPortTcpSsl) {
            this.scanListenerPortTcpSsl = scanListenerPortTcpSsl;
            return this;
        }
        public VmClusterNetworkScan build() {
            final var o = new VmClusterNetworkScan();
            o.hostname = hostname;
            o.ips = ips;
            o.port = port;
            o.scanListenerPortTcp = scanListenerPortTcp;
            o.scanListenerPortTcpSsl = scanListenerPortTcpSsl;
            return o;
        }
    }
}