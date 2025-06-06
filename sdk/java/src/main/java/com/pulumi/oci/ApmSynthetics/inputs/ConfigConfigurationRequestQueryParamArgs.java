// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigConfigurationRequestQueryParamArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfigConfigurationRequestQueryParamArgs Empty = new ConfigConfigurationRequestQueryParamArgs();

    /**
     * (Updatable) Name of request query parameter.
     * 
     */
    @Import(name="paramName")
    private @Nullable Output<String> paramName;

    /**
     * @return (Updatable) Name of request query parameter.
     * 
     */
    public Optional<Output<String>> paramName() {
        return Optional.ofNullable(this.paramName);
    }

    /**
     * (Updatable) Value of request query parameter.
     * 
     */
    @Import(name="paramValue")
    private @Nullable Output<String> paramValue;

    /**
     * @return (Updatable) Value of request query parameter.
     * 
     */
    public Optional<Output<String>> paramValue() {
        return Optional.ofNullable(this.paramValue);
    }

    private ConfigConfigurationRequestQueryParamArgs() {}

    private ConfigConfigurationRequestQueryParamArgs(ConfigConfigurationRequestQueryParamArgs $) {
        this.paramName = $.paramName;
        this.paramValue = $.paramValue;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigConfigurationRequestQueryParamArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigConfigurationRequestQueryParamArgs $;

        public Builder() {
            $ = new ConfigConfigurationRequestQueryParamArgs();
        }

        public Builder(ConfigConfigurationRequestQueryParamArgs defaults) {
            $ = new ConfigConfigurationRequestQueryParamArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param paramName (Updatable) Name of request query parameter.
         * 
         * @return builder
         * 
         */
        public Builder paramName(@Nullable Output<String> paramName) {
            $.paramName = paramName;
            return this;
        }

        /**
         * @param paramName (Updatable) Name of request query parameter.
         * 
         * @return builder
         * 
         */
        public Builder paramName(String paramName) {
            return paramName(Output.of(paramName));
        }

        /**
         * @param paramValue (Updatable) Value of request query parameter.
         * 
         * @return builder
         * 
         */
        public Builder paramValue(@Nullable Output<String> paramValue) {
            $.paramValue = paramValue;
            return this;
        }

        /**
         * @param paramValue (Updatable) Value of request query parameter.
         * 
         * @return builder
         * 
         */
        public Builder paramValue(String paramValue) {
            return paramValue(Output.of(paramValue));
        }

        public ConfigConfigurationRequestQueryParamArgs build() {
            return $;
        }
    }

}
