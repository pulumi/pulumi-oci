// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetSoftwareUpdate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFsuCycleStageActionSchedule {
    /**
     * @return The date and time the Exadata Fleet Update Action is expected to start. [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    private String timeToStart;
    /**
     * @return Type of Exadata Fleet Update Cycle.
     * 
     */
    private String type;

    private GetFsuCycleStageActionSchedule() {}
    /**
     * @return The date and time the Exadata Fleet Update Action is expected to start. [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    public String timeToStart() {
        return this.timeToStart;
    }
    /**
     * @return Type of Exadata Fleet Update Cycle.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFsuCycleStageActionSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String timeToStart;
        private String type;
        public Builder() {}
        public Builder(GetFsuCycleStageActionSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timeToStart = defaults.timeToStart;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder timeToStart(String timeToStart) {
            if (timeToStart == null) {
              throw new MissingRequiredPropertyException("GetFsuCycleStageActionSchedule", "timeToStart");
            }
            this.timeToStart = timeToStart;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetFsuCycleStageActionSchedule", "type");
            }
            this.type = type;
            return this;
        }
        public GetFsuCycleStageActionSchedule build() {
            final var _resultValue = new GetFsuCycleStageActionSchedule();
            _resultValue.timeToStart = timeToStart;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
