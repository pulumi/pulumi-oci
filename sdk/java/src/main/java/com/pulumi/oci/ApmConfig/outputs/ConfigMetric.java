// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmConfig.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ConfigMetric {
    /**
     * @return (Updatable) A description of the metric.
     * 
     */
    private @Nullable String description;
    /**
     * @return (Updatable) The name of the metric. This must be a known metric name.
     * 
     */
    private @Nullable String name;
    /**
     * @return (Updatable) The unit of the metric.
     * 
     */
    private @Nullable String unit;
    /**
     * @return (Updatable) This must not be set.
     * 
     */
    private @Nullable String valueSource;

    private ConfigMetric() {}
    /**
     * @return (Updatable) A description of the metric.
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return (Updatable) The name of the metric. This must be a known metric name.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return (Updatable) The unit of the metric.
     * 
     */
    public Optional<String> unit() {
        return Optional.ofNullable(this.unit);
    }
    /**
     * @return (Updatable) This must not be set.
     * 
     */
    public Optional<String> valueSource() {
        return Optional.ofNullable(this.valueSource);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConfigMetric defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String description;
        private @Nullable String name;
        private @Nullable String unit;
        private @Nullable String valueSource;
        public Builder() {}
        public Builder(ConfigMetric defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.name = defaults.name;
    	      this.unit = defaults.unit;
    	      this.valueSource = defaults.valueSource;
        }

        @CustomType.Setter
        public Builder description(@Nullable String description) {

            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder unit(@Nullable String unit) {

            this.unit = unit;
            return this;
        }
        @CustomType.Setter
        public Builder valueSource(@Nullable String valueSource) {

            this.valueSource = valueSource;
            return this;
        }
        public ConfigMetric build() {
            final var _resultValue = new ConfigMetric();
            _resultValue.description = description;
            _resultValue.name = name;
            _resultValue.unit = unit;
            _resultValue.valueSource = valueSource;
            return _resultValue;
        }
    }
}
