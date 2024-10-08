// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration {
    /**
     * @return Number of hops.
     * 
     */
    private Integer numberOfHops;
    /**
     * @return Type of probe mode when TCP protocol is selected.
     * 
     */
    private String probeMode;
    /**
     * @return Number of probes per hop.
     * 
     */
    private Integer probePerHop;
    /**
     * @return Type of protocol.
     * 
     */
    private String protocol;
    /**
     * @return Number of probe packets sent out simultaneously.
     * 
     */
    private Integer transmissionRate;

    private GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration() {}
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

    public static Builder builder(GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer numberOfHops;
        private String probeMode;
        private Integer probePerHop;
        private String protocol;
        private Integer transmissionRate;
        public Builder() {}
        public Builder(GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.numberOfHops = defaults.numberOfHops;
    	      this.probeMode = defaults.probeMode;
    	      this.probePerHop = defaults.probePerHop;
    	      this.protocol = defaults.protocol;
    	      this.transmissionRate = defaults.transmissionRate;
        }

        @CustomType.Setter
        public Builder numberOfHops(Integer numberOfHops) {
            if (numberOfHops == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration", "numberOfHops");
            }
            this.numberOfHops = numberOfHops;
            return this;
        }
        @CustomType.Setter
        public Builder probeMode(String probeMode) {
            if (probeMode == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration", "probeMode");
            }
            this.probeMode = probeMode;
            return this;
        }
        @CustomType.Setter
        public Builder probePerHop(Integer probePerHop) {
            if (probePerHop == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration", "probePerHop");
            }
            this.probePerHop = probePerHop;
            return this;
        }
        @CustomType.Setter
        public Builder protocol(String protocol) {
            if (protocol == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration", "protocol");
            }
            this.protocol = protocol;
            return this;
        }
        @CustomType.Setter
        public Builder transmissionRate(Integer transmissionRate) {
            if (transmissionRate == null) {
              throw new MissingRequiredPropertyException("GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration", "transmissionRate");
            }
            this.transmissionRate = transmissionRate;
            return this;
        }
        public GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration build() {
            final var _resultValue = new GetMonitorsMonitorCollectionItemConfigurationNetworkConfiguration();
            _resultValue.numberOfHops = numberOfHops;
            _resultValue.probeMode = probeMode;
            _resultValue.probePerHop = probePerHop;
            _resultValue.protocol = protocol;
            _resultValue.transmissionRate = transmissionRate;
            return _resultValue;
        }
    }
}
