// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetVmClusterRecommendedNetworkScan {
    /**
     * @return The node host name.
     * 
     */
    private String hostname;
    /**
     * @return The list of SCAN IP addresses. Three addresses should be provided.
     * 
     */
    private List<String> ips;
    /**
     * @return The SCAN TCPIP port. Default is 1521.
     * 
     */
    private Integer port;
    /**
     * @return The SCAN TCPIP port. Default is 1521.
     * 
     */
    private Integer scanListenerPortTcp;
    /**
     * @return The SCAN TCPIP SSL port. Default is 2484.
     * 
     */
    private Integer scanListenerPortTcpSsl;

    private GetVmClusterRecommendedNetworkScan() {}
    /**
     * @return The node host name.
     * 
     */
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return The list of SCAN IP addresses. Three addresses should be provided.
     * 
     */
    public List<String> ips() {
        return this.ips;
    }
    /**
     * @return The SCAN TCPIP port. Default is 1521.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The SCAN TCPIP port. Default is 1521.
     * 
     */
    public Integer scanListenerPortTcp() {
        return this.scanListenerPortTcp;
    }
    /**
     * @return The SCAN TCPIP SSL port. Default is 2484.
     * 
     */
    public Integer scanListenerPortTcpSsl() {
        return this.scanListenerPortTcpSsl;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVmClusterRecommendedNetworkScan defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostname;
        private List<String> ips;
        private Integer port;
        private Integer scanListenerPortTcp;
        private Integer scanListenerPortTcpSsl;
        public Builder() {}
        public Builder(GetVmClusterRecommendedNetworkScan defaults) {
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
        public Builder scanListenerPortTcp(Integer scanListenerPortTcp) {
            this.scanListenerPortTcp = Objects.requireNonNull(scanListenerPortTcp);
            return this;
        }
        @CustomType.Setter
        public Builder scanListenerPortTcpSsl(Integer scanListenerPortTcpSsl) {
            this.scanListenerPortTcpSsl = Objects.requireNonNull(scanListenerPortTcpSsl);
            return this;
        }
        public GetVmClusterRecommendedNetworkScan build() {
            final var o = new GetVmClusterRecommendedNetworkScan();
            o.hostname = hostname;
            o.ips = ips;
            o.port = port;
            o.scanListenerPortTcp = scanListenerPortTcp;
            o.scanListenerPortTcpSsl = scanListenerPortTcpSsl;
            return o;
        }
    }
}