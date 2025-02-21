// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class VmClusterNetworkDrScan {
    /**
     * @return (Updatable) The Disaster recovery SCAN hostname.
     * 
     */
    private String hostname;
    /**
     * @return (Updatable) The list of Disaster recovery SCAN IP addresses. Three addresses should be provided.
     * 
     */
    private List<String> ips;
    /**
     * @return (Updatable) The Disaster recovery SCAN TCPIP port. Default is 1521.
     * 
     */
    private Integer scanListenerPortTcp;

    private VmClusterNetworkDrScan() {}
    /**
     * @return (Updatable) The Disaster recovery SCAN hostname.
     * 
     */
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return (Updatable) The list of Disaster recovery SCAN IP addresses. Three addresses should be provided.
     * 
     */
    public List<String> ips() {
        return this.ips;
    }
    /**
     * @return (Updatable) The Disaster recovery SCAN TCPIP port. Default is 1521.
     * 
     */
    public Integer scanListenerPortTcp() {
        return this.scanListenerPortTcp;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VmClusterNetworkDrScan defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostname;
        private List<String> ips;
        private Integer scanListenerPortTcp;
        public Builder() {}
        public Builder(VmClusterNetworkDrScan defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostname = defaults.hostname;
    	      this.ips = defaults.ips;
    	      this.scanListenerPortTcp = defaults.scanListenerPortTcp;
        }

        @CustomType.Setter
        public Builder hostname(String hostname) {
            if (hostname == null) {
              throw new MissingRequiredPropertyException("VmClusterNetworkDrScan", "hostname");
            }
            this.hostname = hostname;
            return this;
        }
        @CustomType.Setter
        public Builder ips(List<String> ips) {
            if (ips == null) {
              throw new MissingRequiredPropertyException("VmClusterNetworkDrScan", "ips");
            }
            this.ips = ips;
            return this;
        }
        public Builder ips(String... ips) {
            return ips(List.of(ips));
        }
        @CustomType.Setter
        public Builder scanListenerPortTcp(Integer scanListenerPortTcp) {
            if (scanListenerPortTcp == null) {
              throw new MissingRequiredPropertyException("VmClusterNetworkDrScan", "scanListenerPortTcp");
            }
            this.scanListenerPortTcp = scanListenerPortTcp;
            return this;
        }
        public VmClusterNetworkDrScan build() {
            final var _resultValue = new VmClusterNetworkDrScan();
            _resultValue.hostname = hostname;
            _resultValue.ips = ips;
            _resultValue.scanListenerPortTcp = scanListenerPortTcp;
            return _resultValue;
        }
    }
}
