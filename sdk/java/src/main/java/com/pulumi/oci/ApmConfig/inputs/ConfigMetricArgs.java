// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmConfig.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigMetricArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfigMetricArgs Empty = new ConfigMetricArgs();

    /**
     * (Updatable) A description of the metric.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A description of the metric.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) The name of the metric. This must be a known metric name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) The name of the metric. This must be a known metric name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) The unit of the metric.
     * 
     */
    @Import(name="unit")
    private @Nullable Output<String> unit;

    /**
     * @return (Updatable) The unit of the metric.
     * 
     */
    public Optional<Output<String>> unit() {
        return Optional.ofNullable(this.unit);
    }

    /**
     * (Updatable) This must not be set.
     * 
     */
    @Import(name="valueSource")
    private @Nullable Output<String> valueSource;

    /**
     * @return (Updatable) This must not be set.
     * 
     */
    public Optional<Output<String>> valueSource() {
        return Optional.ofNullable(this.valueSource);
    }

    private ConfigMetricArgs() {}

    private ConfigMetricArgs(ConfigMetricArgs $) {
        this.description = $.description;
        this.name = $.name;
        this.unit = $.unit;
        this.valueSource = $.valueSource;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigMetricArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigMetricArgs $;

        public Builder() {
            $ = new ConfigMetricArgs();
        }

        public Builder(ConfigMetricArgs defaults) {
            $ = new ConfigMetricArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param description (Updatable) A description of the metric.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A description of the metric.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param name (Updatable) The name of the metric. This must be a known metric name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name of the metric. This must be a known metric name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param unit (Updatable) The unit of the metric.
         * 
         * @return builder
         * 
         */
        public Builder unit(@Nullable Output<String> unit) {
            $.unit = unit;
            return this;
        }

        /**
         * @param unit (Updatable) The unit of the metric.
         * 
         * @return builder
         * 
         */
        public Builder unit(String unit) {
            return unit(Output.of(unit));
        }

        /**
         * @param valueSource (Updatable) This must not be set.
         * 
         * @return builder
         * 
         */
        public Builder valueSource(@Nullable Output<String> valueSource) {
            $.valueSource = valueSource;
            return this;
        }

        /**
         * @param valueSource (Updatable) This must not be set.
         * 
         * @return builder
         * 
         */
        public Builder valueSource(String valueSource) {
            return valueSource(Output.of(valueSource));
        }

        public ConfigMetricArgs build() {
            return $;
        }
    }

}
