// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs Empty = new MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs();

    /**
     * Property name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Property name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Property value.
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return Property value.
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs() {}

    private MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs(MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs $) {
        this.name = $.name;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs $;

        public Builder() {
            $ = new MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs();
        }

        public Builder(MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs defaults) {
            $ = new MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name Property name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Property name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param value Property value.
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value Property value.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs build() {
            return $;
        }
    }

}
