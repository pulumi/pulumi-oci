// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCrossConnectStatusResult {
    /**
     * @return The OCID of the cross-connect.
     * 
     */
    private String crossConnectId;
    /**
     * @return Encryption status of the CrossConnect
     * 
     */
    private String encryptionStatus;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Whether Oracle&#39;s side of the interface is up or down.
     * 
     */
    private String interfaceState;
    /**
     * @return The light level of the cross-connect (in dBm).  Example: `14.0`
     * 
     */
    private Double lightLevelIndBm;
    /**
     * @return Status indicator corresponding to the light level.
     * * **NO_LIGHT:** No measurable light
     * * **LOW_WARN:** There&#39;s measurable light but it&#39;s too low
     * * **HIGH_WARN:** Light level is too high
     * * **BAD:** There&#39;s measurable light but the signal-to-noise ratio is bad
     * * **GOOD:** Good light level
     * 
     */
    private String lightLevelIndicator;

    private GetCrossConnectStatusResult() {}
    /**
     * @return The OCID of the cross-connect.
     * 
     */
    public String crossConnectId() {
        return this.crossConnectId;
    }
    /**
     * @return Encryption status of the CrossConnect
     * 
     */
    public String encryptionStatus() {
        return this.encryptionStatus;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Whether Oracle&#39;s side of the interface is up or down.
     * 
     */
    public String interfaceState() {
        return this.interfaceState;
    }
    /**
     * @return The light level of the cross-connect (in dBm).  Example: `14.0`
     * 
     */
    public Double lightLevelIndBm() {
        return this.lightLevelIndBm;
    }
    /**
     * @return Status indicator corresponding to the light level.
     * * **NO_LIGHT:** No measurable light
     * * **LOW_WARN:** There&#39;s measurable light but it&#39;s too low
     * * **HIGH_WARN:** Light level is too high
     * * **BAD:** There&#39;s measurable light but the signal-to-noise ratio is bad
     * * **GOOD:** Good light level
     * 
     */
    public String lightLevelIndicator() {
        return this.lightLevelIndicator;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCrossConnectStatusResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String crossConnectId;
        private String encryptionStatus;
        private String id;
        private String interfaceState;
        private Double lightLevelIndBm;
        private String lightLevelIndicator;
        public Builder() {}
        public Builder(GetCrossConnectStatusResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.crossConnectId = defaults.crossConnectId;
    	      this.encryptionStatus = defaults.encryptionStatus;
    	      this.id = defaults.id;
    	      this.interfaceState = defaults.interfaceState;
    	      this.lightLevelIndBm = defaults.lightLevelIndBm;
    	      this.lightLevelIndicator = defaults.lightLevelIndicator;
        }

        @CustomType.Setter
        public Builder crossConnectId(String crossConnectId) {
            this.crossConnectId = Objects.requireNonNull(crossConnectId);
            return this;
        }
        @CustomType.Setter
        public Builder encryptionStatus(String encryptionStatus) {
            this.encryptionStatus = Objects.requireNonNull(encryptionStatus);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder interfaceState(String interfaceState) {
            this.interfaceState = Objects.requireNonNull(interfaceState);
            return this;
        }
        @CustomType.Setter
        public Builder lightLevelIndBm(Double lightLevelIndBm) {
            this.lightLevelIndBm = Objects.requireNonNull(lightLevelIndBm);
            return this;
        }
        @CustomType.Setter
        public Builder lightLevelIndicator(String lightLevelIndicator) {
            this.lightLevelIndicator = Objects.requireNonNull(lightLevelIndicator);
            return this;
        }
        public GetCrossConnectStatusResult build() {
            final var o = new GetCrossConnectStatusResult();
            o.crossConnectId = crossConnectId;
            o.encryptionStatus = encryptionStatus;
            o.id = id;
            o.interfaceState = interfaceState;
            o.lightLevelIndBm = lightLevelIndBm;
            o.lightLevelIndicator = lightLevelIndicator;
            return o;
        }
    }
}