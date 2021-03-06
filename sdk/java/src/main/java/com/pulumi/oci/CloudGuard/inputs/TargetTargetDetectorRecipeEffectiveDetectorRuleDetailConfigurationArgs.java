// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudGuard.inputs.TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValueArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs Empty = new TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs();

    /**
     * (Updatable) Unique name of the configuration
     * 
     */
    @Import(name="configKey")
    private @Nullable Output<String> configKey;

    /**
     * @return (Updatable) Unique name of the configuration
     * 
     */
    public Optional<Output<String>> configKey() {
        return Optional.ofNullable(this.configKey);
    }

    /**
     * configuration data type
     * 
     */
    @Import(name="dataType")
    private @Nullable Output<String> dataType;

    /**
     * @return configuration data type
     * 
     */
    public Optional<Output<String>> dataType() {
        return Optional.ofNullable(this.dataType);
    }

    /**
     * (Updatable) configuration name
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) configuration name
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) configuration value
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return (Updatable) configuration value
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    /**
     * List of configuration values
     * 
     */
    @Import(name="values")
    private @Nullable Output<List<TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValueArgs>> values;

    /**
     * @return List of configuration values
     * 
     */
    public Optional<Output<List<TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValueArgs>>> values() {
        return Optional.ofNullable(this.values);
    }

    private TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs() {}

    private TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs(TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs $) {
        this.configKey = $.configKey;
        this.dataType = $.dataType;
        this.name = $.name;
        this.value = $.value;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs $;

        public Builder() {
            $ = new TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs();
        }

        public Builder(TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs defaults) {
            $ = new TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param configKey (Updatable) Unique name of the configuration
         * 
         * @return builder
         * 
         */
        public Builder configKey(@Nullable Output<String> configKey) {
            $.configKey = configKey;
            return this;
        }

        /**
         * @param configKey (Updatable) Unique name of the configuration
         * 
         * @return builder
         * 
         */
        public Builder configKey(String configKey) {
            return configKey(Output.of(configKey));
        }

        /**
         * @param dataType configuration data type
         * 
         * @return builder
         * 
         */
        public Builder dataType(@Nullable Output<String> dataType) {
            $.dataType = dataType;
            return this;
        }

        /**
         * @param dataType configuration data type
         * 
         * @return builder
         * 
         */
        public Builder dataType(String dataType) {
            return dataType(Output.of(dataType));
        }

        /**
         * @param name (Updatable) configuration name
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) configuration name
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param value (Updatable) configuration value
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) configuration value
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        /**
         * @param values List of configuration values
         * 
         * @return builder
         * 
         */
        public Builder values(@Nullable Output<List<TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValueArgs>> values) {
            $.values = values;
            return this;
        }

        /**
         * @param values List of configuration values
         * 
         * @return builder
         * 
         */
        public Builder values(List<TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValueArgs> values) {
            return values(Output.of(values));
        }

        /**
         * @param values List of configuration values
         * 
         * @return builder
         * 
         */
        public Builder values(TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationValueArgs... values) {
            return values(List.of(values));
        }

        public TargetTargetDetectorRecipeEffectiveDetectorRuleDetailConfigurationArgs build() {
            return $;
        }
    }

}
