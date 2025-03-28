// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetIpsecStatusTunnel {
    /**
     * @return The IP address of Oracle&#39;s VPN headend.  Example: `203.0.113.50`
     * 
     */
    private String ipAddress;
    /**
     * @return The tunnel&#39;s current state.
     * 
     */
    private String state;
    /**
     * @return The date and time the IPSec connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return When the state of the tunnel last changed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeStateModified;

    private GetIpsecStatusTunnel() {}
    /**
     * @return The IP address of Oracle&#39;s VPN headend.  Example: `203.0.113.50`
     * 
     */
    public String ipAddress() {
        return this.ipAddress;
    }
    /**
     * @return The tunnel&#39;s current state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the IPSec connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return When the state of the tunnel last changed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeStateModified() {
        return this.timeStateModified;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpsecStatusTunnel defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ipAddress;
        private String state;
        private String timeCreated;
        private String timeStateModified;
        public Builder() {}
        public Builder(GetIpsecStatusTunnel defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ipAddress = defaults.ipAddress;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeStateModified = defaults.timeStateModified;
        }

        @CustomType.Setter
        public Builder ipAddress(String ipAddress) {
            if (ipAddress == null) {
              throw new MissingRequiredPropertyException("GetIpsecStatusTunnel", "ipAddress");
            }
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetIpsecStatusTunnel", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetIpsecStatusTunnel", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeStateModified(String timeStateModified) {
            if (timeStateModified == null) {
              throw new MissingRequiredPropertyException("GetIpsecStatusTunnel", "timeStateModified");
            }
            this.timeStateModified = timeStateModified;
            return this;
        }
        public GetIpsecStatusTunnel build() {
            final var _resultValue = new GetIpsecStatusTunnel();
            _resultValue.ipAddress = ipAddress;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeStateModified = timeStateModified;
            return _resultValue;
        }
    }
}
