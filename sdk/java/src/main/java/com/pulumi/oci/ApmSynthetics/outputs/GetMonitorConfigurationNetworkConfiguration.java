// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMonitorConfigurationNetworkConfiguration {
    /**
     * @return Number of hops.
     * 
     */
    private final Integer numberOfHops;
    /**
     * @return Type of probe mode when TCP protocol is selected.
     * 
     */
    private final String probeMode;
    /**
     * @return Number of probes per hop.
     * 
     */
    private final Integer probePerHop;
    /**
     * @return Type of protocol.
     * 
     */
    private final String protocol;
    /**
     * @return Number of probe packets sent out simultaneously.
     * 
     */
    private final Integer transmissionRate;

    @CustomType.Constructor
    private GetMonitorConfigurationNetworkConfiguration(
        @CustomType.Parameter("numberOfHops") Integer numberOfHops,
        @CustomType.Parameter("probeMode") String probeMode,
        @CustomType.Parameter("probePerHop") Integer probePerHop,
        @CustomType.Parameter("protocol") String protocol,
        @CustomType.Parameter("transmissionRate") Integer transmissionRate) {
        this.numberOfHops = numberOfHops;
        this.probeMode = probeMode;
        this.probePerHop = probePerHop;
        this.protocol = protocol;
        this.transmissionRate = transmissionRate;
    }

    /**
     * @return Number of hops.
     * 
     */
    public Integer numberOfHops() {
        return this.numberOfHops;
    }
    /**
     * @return Type of probe mode when TCP protocol is selected.
     * 
     */
    public String probeMode() {
        return this.probeMode;
    }
    /**
     * @return Number of probes per hop.
     * 
     */
    public Integer probePerHop() {
        return this.probePerHop;
    }
    /**
     * @return Type of protocol.
     * 
     */
    public String protocol() {
        return this.protocol;
    }
    /**
     * @return Number of probe packets sent out simultaneously.
     * 
     */
    public Integer transmissionRate() {
        return this.transmissionRate;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitorConfigurationNetworkConfiguration defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer numberOfHops;
        private String probeMode;
        private Integer probePerHop;
        private String protocol;
        private Integer transmissionRate;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMonitorConfigurationNetworkConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.numberOfHops = defaults.numberOfHops;
    	      this.probeMode = defaults.probeMode;
    	      this.probePerHop = defaults.probePerHop;
    	      this.protocol = defaults.protocol;
    	      this.transmissionRate = defaults.transmissionRate;
        }

        public Builder numberOfHops(Integer numberOfHops) {
            this.numberOfHops = Objects.requireNonNull(numberOfHops);
            return this;
        }
        public Builder probeMode(String probeMode) {
            this.probeMode = Objects.requireNonNull(probeMode);
            return this;
        }
        public Builder probePerHop(Integer probePerHop) {
            this.probePerHop = Objects.requireNonNull(probePerHop);
            return this;
        }
        public Builder protocol(String protocol) {
            this.protocol = Objects.requireNonNull(protocol);
            return this;
        }
        public Builder transmissionRate(Integer transmissionRate) {
            this.transmissionRate = Objects.requireNonNull(transmissionRate);
            return this;
        }        public GetMonitorConfigurationNetworkConfiguration build() {
            return new GetMonitorConfigurationNetworkConfiguration(numberOfHops, probeMode, probePerHop, protocol, transmissionRate);
        }
    }
}
