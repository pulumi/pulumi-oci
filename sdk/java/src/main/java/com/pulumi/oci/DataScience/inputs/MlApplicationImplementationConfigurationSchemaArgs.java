// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MlApplicationImplementationConfigurationSchemaArgs extends com.pulumi.resources.ResourceArgs {

    public static final MlApplicationImplementationConfigurationSchemaArgs Empty = new MlApplicationImplementationConfigurationSchemaArgs();

    /**
     * The default value for the optional configuration property (it must not be specified for mandatory configuration properties)
     * 
     */
    @Import(name="defaultValue")
    private @Nullable Output<String> defaultValue;

    /**
     * @return The default value for the optional configuration property (it must not be specified for mandatory configuration properties)
     * 
     */
    public Optional<Output<String>> defaultValue() {
        return Optional.ofNullable(this.defaultValue);
    }

    /**
     * short description of the argument
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return short description of the argument
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * argument is mandatory or not
     * 
     */
    @Import(name="isMandatory")
    private @Nullable Output<Boolean> isMandatory;

    /**
     * @return argument is mandatory or not
     * 
     */
    public Optional<Output<Boolean>> isMandatory() {
        return Optional.ofNullable(this.isMandatory);
    }

    /**
     * Name of key (parameter name)
     * 
     */
    @Import(name="keyName")
    private @Nullable Output<String> keyName;

    /**
     * @return Name of key (parameter name)
     * 
     */
    public Optional<Output<String>> keyName() {
        return Optional.ofNullable(this.keyName);
    }

    /**
     * Sample property value (it must match validationRegexp if it is specified)
     * 
     */
    @Import(name="sampleValue")
    private @Nullable Output<String> sampleValue;

    /**
     * @return Sample property value (it must match validationRegexp if it is specified)
     * 
     */
    public Optional<Output<String>> sampleValue() {
        return Optional.ofNullable(this.sampleValue);
    }

    /**
     * A regular expression will be used for the validation of property value.
     * 
     */
    @Import(name="validationRegexp")
    private @Nullable Output<String> validationRegexp;

    /**
     * @return A regular expression will be used for the validation of property value.
     * 
     */
    public Optional<Output<String>> validationRegexp() {
        return Optional.ofNullable(this.validationRegexp);
    }

    /**
     * Type of value
     * 
     */
    @Import(name="valueType")
    private @Nullable Output<String> valueType;

    /**
     * @return Type of value
     * 
     */
    public Optional<Output<String>> valueType() {
        return Optional.ofNullable(this.valueType);
    }

    private MlApplicationImplementationConfigurationSchemaArgs() {}

    private MlApplicationImplementationConfigurationSchemaArgs(MlApplicationImplementationConfigurationSchemaArgs $) {
        this.defaultValue = $.defaultValue;
        this.description = $.description;
        this.isMandatory = $.isMandatory;
        this.keyName = $.keyName;
        this.sampleValue = $.sampleValue;
        this.validationRegexp = $.validationRegexp;
        this.valueType = $.valueType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MlApplicationImplementationConfigurationSchemaArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MlApplicationImplementationConfigurationSchemaArgs $;

        public Builder() {
            $ = new MlApplicationImplementationConfigurationSchemaArgs();
        }

        public Builder(MlApplicationImplementationConfigurationSchemaArgs defaults) {
            $ = new MlApplicationImplementationConfigurationSchemaArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param defaultValue The default value for the optional configuration property (it must not be specified for mandatory configuration properties)
         * 
         * @return builder
         * 
         */
        public Builder defaultValue(@Nullable Output<String> defaultValue) {
            $.defaultValue = defaultValue;
            return this;
        }

        /**
         * @param defaultValue The default value for the optional configuration property (it must not be specified for mandatory configuration properties)
         * 
         * @return builder
         * 
         */
        public Builder defaultValue(String defaultValue) {
            return defaultValue(Output.of(defaultValue));
        }

        /**
         * @param description short description of the argument
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description short description of the argument
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param isMandatory argument is mandatory or not
         * 
         * @return builder
         * 
         */
        public Builder isMandatory(@Nullable Output<Boolean> isMandatory) {
            $.isMandatory = isMandatory;
            return this;
        }

        /**
         * @param isMandatory argument is mandatory or not
         * 
         * @return builder
         * 
         */
        public Builder isMandatory(Boolean isMandatory) {
            return isMandatory(Output.of(isMandatory));
        }

        /**
         * @param keyName Name of key (parameter name)
         * 
         * @return builder
         * 
         */
        public Builder keyName(@Nullable Output<String> keyName) {
            $.keyName = keyName;
            return this;
        }

        /**
         * @param keyName Name of key (parameter name)
         * 
         * @return builder
         * 
         */
        public Builder keyName(String keyName) {
            return keyName(Output.of(keyName));
        }

        /**
         * @param sampleValue Sample property value (it must match validationRegexp if it is specified)
         * 
         * @return builder
         * 
         */
        public Builder sampleValue(@Nullable Output<String> sampleValue) {
            $.sampleValue = sampleValue;
            return this;
        }

        /**
         * @param sampleValue Sample property value (it must match validationRegexp if it is specified)
         * 
         * @return builder
         * 
         */
        public Builder sampleValue(String sampleValue) {
            return sampleValue(Output.of(sampleValue));
        }

        /**
         * @param validationRegexp A regular expression will be used for the validation of property value.
         * 
         * @return builder
         * 
         */
        public Builder validationRegexp(@Nullable Output<String> validationRegexp) {
            $.validationRegexp = validationRegexp;
            return this;
        }

        /**
         * @param validationRegexp A regular expression will be used for the validation of property value.
         * 
         * @return builder
         * 
         */
        public Builder validationRegexp(String validationRegexp) {
            return validationRegexp(Output.of(validationRegexp));
        }

        /**
         * @param valueType Type of value
         * 
         * @return builder
         * 
         */
        public Builder valueType(@Nullable Output<String> valueType) {
            $.valueType = valueType;
            return this;
        }

        /**
         * @param valueType Type of value
         * 
         * @return builder
         * 
         */
        public Builder valueType(String valueType) {
            return valueType(Output.of(valueType));
        }

        public MlApplicationImplementationConfigurationSchemaArgs build() {
            return $;
        }
    }

}
