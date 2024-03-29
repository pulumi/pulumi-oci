// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetHeatWaveClusterClusterNode {
    /**
     * @return The ID of the node within MySQL HeatWave cluster.
     * 
     */
    private String nodeId;
    /**
     * @return The current state of the HeatWave cluster.
     * 
     */
    private String state;
    /**
     * @return The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    private String timeCreated;
    /**
     * @return The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    private String timeUpdated;

    private GetHeatWaveClusterClusterNode() {}
    /**
     * @return The ID of the node within MySQL HeatWave cluster.
     * 
     */
    public String nodeId() {
        return this.nodeId;
    }
    /**
     * @return The current state of the HeatWave cluster.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the HeatWave cluster was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the HeatWave cluster was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetHeatWaveClusterClusterNode defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String nodeId;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetHeatWaveClusterClusterNode defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.nodeId = defaults.nodeId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder nodeId(String nodeId) {
            if (nodeId == null) {
              throw new MissingRequiredPropertyException("GetHeatWaveClusterClusterNode", "nodeId");
            }
            this.nodeId = nodeId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetHeatWaveClusterClusterNode", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetHeatWaveClusterClusterNode", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetHeatWaveClusterClusterNode", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetHeatWaveClusterClusterNode build() {
            final var _resultValue = new GetHeatWaveClusterClusterNode();
            _resultValue.nodeId = nodeId;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
