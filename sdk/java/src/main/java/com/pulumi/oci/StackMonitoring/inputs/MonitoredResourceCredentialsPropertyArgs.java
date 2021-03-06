// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MonitoredResourceCredentialsPropertyArgs extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourceCredentialsPropertyArgs Empty = new MonitoredResourceCredentialsPropertyArgs();

    /**
     * (Updatable) property name
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) property name
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) property value
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return (Updatable) property value
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private MonitoredResourceCredentialsPropertyArgs() {}

    private MonitoredResourceCredentialsPropertyArgs(MonitoredResourceCredentialsPropertyArgs $) {
        this.name = $.name;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoredResourceCredentialsPropertyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourceCredentialsPropertyArgs $;

        public Builder() {
            $ = new MonitoredResourceCredentialsPropertyArgs();
        }

        public Builder(MonitoredResourceCredentialsPropertyArgs defaults) {
            $ = new MonitoredResourceCredentialsPropertyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name (Updatable) property name
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) property name
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param value (Updatable) property value
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) property value
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public MonitoredResourceCredentialsPropertyArgs build() {
            return $;
        }
    }

}
