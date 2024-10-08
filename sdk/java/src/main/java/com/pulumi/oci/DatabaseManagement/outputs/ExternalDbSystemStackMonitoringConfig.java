// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExternalDbSystemStackMonitoringConfig {
    /**
     * @return The status of the associated service.
     * 
     */
    private Boolean isEnabled;
    /**
     * @return The associated service-specific inputs in JSON string format, which Database Management can identify.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private @Nullable String metadata;

    private ExternalDbSystemStackMonitoringConfig() {}
    /**
     * @return The status of the associated service.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }
    /**
     * @return The associated service-specific inputs in JSON string format, which Database Management can identify.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<String> metadata() {
        return Optional.ofNullable(this.metadata);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExternalDbSystemStackMonitoringConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isEnabled;
        private @Nullable String metadata;
        public Builder() {}
        public Builder(ExternalDbSystemStackMonitoringConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isEnabled = defaults.isEnabled;
    	      this.metadata = defaults.metadata;
        }

        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            if (isEnabled == null) {
              throw new MissingRequiredPropertyException("ExternalDbSystemStackMonitoringConfig", "isEnabled");
            }
            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder metadata(@Nullable String metadata) {

            this.metadata = metadata;
            return this;
        }
        public ExternalDbSystemStackMonitoringConfig build() {
            final var _resultValue = new ExternalDbSystemStackMonitoringConfig();
            _resultValue.isEnabled = isEnabled;
            _resultValue.metadata = metadata;
            return _resultValue;
        }
    }
}
