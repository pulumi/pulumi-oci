// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.HealthChecks.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetHttpProbeResultsHttpProbeResultConnection {
    /**
     * @return The connection IP address.
     * 
     */
    private String address;
    /**
     * @return Total connect duration, calculated using `connectEnd` minus `connectStart`.
     * 
     */
    private Double connectDuration;
    /**
     * @return The port.
     * 
     */
    private Integer port;
    /**
     * @return The duration to secure the connection.  This value will be zero for insecure connections.  Calculated using `connectEnd` minus `secureConnectionStart`.
     * 
     */
    private Double secureConnectDuration;

    private GetHttpProbeResultsHttpProbeResultConnection() {}
    /**
     * @return The connection IP address.
     * 
     */
    public String address() {
        return this.address;
    }
    /**
     * @return Total connect duration, calculated using `connectEnd` minus `connectStart`.
     * 
     */
    public Double connectDuration() {
        return this.connectDuration;
    }
    /**
     * @return The port.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The duration to secure the connection.  This value will be zero for insecure connections.  Calculated using `connectEnd` minus `secureConnectionStart`.
     * 
     */
    public Double secureConnectDuration() {
        return this.secureConnectDuration;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetHttpProbeResultsHttpProbeResultConnection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String address;
        private Double connectDuration;
        private Integer port;
        private Double secureConnectDuration;
        public Builder() {}
        public Builder(GetHttpProbeResultsHttpProbeResultConnection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.address = defaults.address;
    	      this.connectDuration = defaults.connectDuration;
    	      this.port = defaults.port;
    	      this.secureConnectDuration = defaults.secureConnectDuration;
        }

        @CustomType.Setter
        public Builder address(String address) {
            this.address = Objects.requireNonNull(address);
            return this;
        }
        @CustomType.Setter
        public Builder connectDuration(Double connectDuration) {
            this.connectDuration = Objects.requireNonNull(connectDuration);
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            this.port = Objects.requireNonNull(port);
            return this;
        }
        @CustomType.Setter
        public Builder secureConnectDuration(Double secureConnectDuration) {
            this.secureConnectDuration = Objects.requireNonNull(secureConnectDuration);
            return this;
        }
        public GetHttpProbeResultsHttpProbeResultConnection build() {
            final var o = new GetHttpProbeResultsHttpProbeResultConnection();
            o.address = address;
            o.connectDuration = connectDuration;
            o.port = port;
            o.secureConnectDuration = secureConnectDuration;
            return o;
        }
    }
}