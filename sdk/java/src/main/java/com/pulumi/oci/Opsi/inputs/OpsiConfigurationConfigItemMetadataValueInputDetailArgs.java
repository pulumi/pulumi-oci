// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class OpsiConfigurationConfigItemMetadataValueInputDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final OpsiConfigurationConfigItemMetadataValueInputDetailArgs Empty = new OpsiConfigurationConfigItemMetadataValueInputDetailArgs();

    /**
     * Allowed value type of configuration item.
     * 
     */
    @Import(name="allowedValueType")
    private @Nullable Output<String> allowedValueType;

    /**
     * @return Allowed value type of configuration item.
     * 
     */
    public Optional<Output<String>> allowedValueType() {
        return Optional.ofNullable(this.allowedValueType);
    }

    /**
     * Maximum value limit for the configuration item.
     * 
     */
    @Import(name="maxValue")
    private @Nullable Output<String> maxValue;

    /**
     * @return Maximum value limit for the configuration item.
     * 
     */
    public Optional<Output<String>> maxValue() {
        return Optional.ofNullable(this.maxValue);
    }

    /**
     * Minimum value limit for the configuration item.
     * 
     */
    @Import(name="minValue")
    private @Nullable Output<String> minValue;

    /**
     * @return Minimum value limit for the configuration item.
     * 
     */
    public Optional<Output<String>> minValue() {
        return Optional.ofNullable(this.minValue);
    }

    /**
     * Allowed values to pick for the configuration item.
     * 
     */
    @Import(name="possibleValues")
    private @Nullable Output<List<String>> possibleValues;

    /**
     * @return Allowed values to pick for the configuration item.
     * 
     */
    public Optional<Output<List<String>>> possibleValues() {
        return Optional.ofNullable(this.possibleValues);
    }

    private OpsiConfigurationConfigItemMetadataValueInputDetailArgs() {}

    private OpsiConfigurationConfigItemMetadataValueInputDetailArgs(OpsiConfigurationConfigItemMetadataValueInputDetailArgs $) {
        this.allowedValueType = $.allowedValueType;
        this.maxValue = $.maxValue;
        this.minValue = $.minValue;
        this.possibleValues = $.possibleValues;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(OpsiConfigurationConfigItemMetadataValueInputDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private OpsiConfigurationConfigItemMetadataValueInputDetailArgs $;

        public Builder() {
            $ = new OpsiConfigurationConfigItemMetadataValueInputDetailArgs();
        }

        public Builder(OpsiConfigurationConfigItemMetadataValueInputDetailArgs defaults) {
            $ = new OpsiConfigurationConfigItemMetadataValueInputDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param allowedValueType Allowed value type of configuration item.
         * 
         * @return builder
         * 
         */
        public Builder allowedValueType(@Nullable Output<String> allowedValueType) {
            $.allowedValueType = allowedValueType;
            return this;
        }

        /**
         * @param allowedValueType Allowed value type of configuration item.
         * 
         * @return builder
         * 
         */
        public Builder allowedValueType(String allowedValueType) {
            return allowedValueType(Output.of(allowedValueType));
        }

        /**
         * @param maxValue Maximum value limit for the configuration item.
         * 
         * @return builder
         * 
         */
        public Builder maxValue(@Nullable Output<String> maxValue) {
            $.maxValue = maxValue;
            return this;
        }

        /**
         * @param maxValue Maximum value limit for the configuration item.
         * 
         * @return builder
         * 
         */
        public Builder maxValue(String maxValue) {
            return maxValue(Output.of(maxValue));
        }

        /**
         * @param minValue Minimum value limit for the configuration item.
         * 
         * @return builder
         * 
         */
        public Builder minValue(@Nullable Output<String> minValue) {
            $.minValue = minValue;
            return this;
        }

        /**
         * @param minValue Minimum value limit for the configuration item.
         * 
         * @return builder
         * 
         */
        public Builder minValue(String minValue) {
            return minValue(Output.of(minValue));
        }

        /**
         * @param possibleValues Allowed values to pick for the configuration item.
         * 
         * @return builder
         * 
         */
        public Builder possibleValues(@Nullable Output<List<String>> possibleValues) {
            $.possibleValues = possibleValues;
            return this;
        }

        /**
         * @param possibleValues Allowed values to pick for the configuration item.
         * 
         * @return builder
         * 
         */
        public Builder possibleValues(List<String> possibleValues) {
            return possibleValues(Output.of(possibleValues));
        }

        /**
         * @param possibleValues Allowed values to pick for the configuration item.
         * 
         * @return builder
         * 
         */
        public Builder possibleValues(String... possibleValues) {
            return possibleValues(List.of(possibleValues));
        }

        public OpsiConfigurationConfigItemMetadataValueInputDetailArgs build() {
            return $;
        }
    }

}
