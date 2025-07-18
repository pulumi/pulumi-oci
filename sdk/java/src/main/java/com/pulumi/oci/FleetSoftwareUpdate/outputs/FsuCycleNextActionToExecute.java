// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetSoftwareUpdate.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class FsuCycleNextActionToExecute {
    /**
     * @return The date and time the Exadata Fleet Update Action is expected to start. [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    private @Nullable String timeToStart;
    /**
     * @return (Updatable) Type of Exadata Fleet Update Cycle.
     * 
     */
    private @Nullable String type;

    private FsuCycleNextActionToExecute() {}
    /**
     * @return The date and time the Exadata Fleet Update Action is expected to start. [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     * 
     */
    public Optional<String> timeToStart() {
        return Optional.ofNullable(this.timeToStart);
    }
    /**
     * @return (Updatable) Type of Exadata Fleet Update Cycle.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FsuCycleNextActionToExecute defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String timeToStart;
        private @Nullable String type;
        public Builder() {}
        public Builder(FsuCycleNextActionToExecute defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timeToStart = defaults.timeToStart;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder timeToStart(@Nullable String timeToStart) {

            this.timeToStart = timeToStart;
            return this;
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {

            this.type = type;
            return this;
        }
        public FsuCycleNextActionToExecute build() {
            final var _resultValue = new FsuCycleNextActionToExecute();
            _resultValue.timeToStart = timeToStart;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
