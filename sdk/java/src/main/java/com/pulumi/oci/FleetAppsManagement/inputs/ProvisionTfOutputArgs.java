// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ProvisionTfOutputArgs extends com.pulumi.resources.ResourceArgs {

    public static final ProvisionTfOutputArgs Empty = new ProvisionTfOutputArgs();

    /**
     * The indicator if the data for this parameter is sensitive (e.g. should the data be hidden in UI, encrypted if stored, etc.)
     * 
     */
    @Import(name="isSensitive")
    private @Nullable Output<Boolean> isSensitive;

    /**
     * @return The indicator if the data for this parameter is sensitive (e.g. should the data be hidden in UI, encrypted if stored, etc.)
     * 
     */
    public Optional<Output<Boolean>> isSensitive() {
        return Optional.ofNullable(this.isSensitive);
    }

    /**
     * The output description
     * 
     */
    @Import(name="outputDescription")
    private @Nullable Output<String> outputDescription;

    /**
     * @return The output description
     * 
     */
    public Optional<Output<String>> outputDescription() {
        return Optional.ofNullable(this.outputDescription);
    }

    /**
     * The output name
     * 
     */
    @Import(name="outputName")
    private @Nullable Output<String> outputName;

    /**
     * @return The output name
     * 
     */
    public Optional<Output<String>> outputName() {
        return Optional.ofNullable(this.outputName);
    }

    /**
     * The output type
     * 
     */
    @Import(name="outputType")
    private @Nullable Output<String> outputType;

    /**
     * @return The output type
     * 
     */
    public Optional<Output<String>> outputType() {
        return Optional.ofNullable(this.outputType);
    }

    /**
     * The output value
     * 
     */
    @Import(name="outputValue")
    private @Nullable Output<String> outputValue;

    /**
     * @return The output value
     * 
     */
    public Optional<Output<String>> outputValue() {
        return Optional.ofNullable(this.outputValue);
    }

    private ProvisionTfOutputArgs() {}

    private ProvisionTfOutputArgs(ProvisionTfOutputArgs $) {
        this.isSensitive = $.isSensitive;
        this.outputDescription = $.outputDescription;
        this.outputName = $.outputName;
        this.outputType = $.outputType;
        this.outputValue = $.outputValue;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ProvisionTfOutputArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ProvisionTfOutputArgs $;

        public Builder() {
            $ = new ProvisionTfOutputArgs();
        }

        public Builder(ProvisionTfOutputArgs defaults) {
            $ = new ProvisionTfOutputArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isSensitive The indicator if the data for this parameter is sensitive (e.g. should the data be hidden in UI, encrypted if stored, etc.)
         * 
         * @return builder
         * 
         */
        public Builder isSensitive(@Nullable Output<Boolean> isSensitive) {
            $.isSensitive = isSensitive;
            return this;
        }

        /**
         * @param isSensitive The indicator if the data for this parameter is sensitive (e.g. should the data be hidden in UI, encrypted if stored, etc.)
         * 
         * @return builder
         * 
         */
        public Builder isSensitive(Boolean isSensitive) {
            return isSensitive(Output.of(isSensitive));
        }

        /**
         * @param outputDescription The output description
         * 
         * @return builder
         * 
         */
        public Builder outputDescription(@Nullable Output<String> outputDescription) {
            $.outputDescription = outputDescription;
            return this;
        }

        /**
         * @param outputDescription The output description
         * 
         * @return builder
         * 
         */
        public Builder outputDescription(String outputDescription) {
            return outputDescription(Output.of(outputDescription));
        }

        /**
         * @param outputName The output name
         * 
         * @return builder
         * 
         */
        public Builder outputName(@Nullable Output<String> outputName) {
            $.outputName = outputName;
            return this;
        }

        /**
         * @param outputName The output name
         * 
         * @return builder
         * 
         */
        public Builder outputName(String outputName) {
            return outputName(Output.of(outputName));
        }

        /**
         * @param outputType The output type
         * 
         * @return builder
         * 
         */
        public Builder outputType(@Nullable Output<String> outputType) {
            $.outputType = outputType;
            return this;
        }

        /**
         * @param outputType The output type
         * 
         * @return builder
         * 
         */
        public Builder outputType(String outputType) {
            return outputType(Output.of(outputType));
        }

        /**
         * @param outputValue The output value
         * 
         * @return builder
         * 
         */
        public Builder outputValue(@Nullable Output<String> outputValue) {
            $.outputValue = outputValue;
            return this;
        }

        /**
         * @param outputValue The output value
         * 
         * @return builder
         * 
         */
        public Builder outputValue(String outputValue) {
            return outputValue(Output.of(outputValue));
        }

        public ProvisionTfOutputArgs build() {
            return $;
        }
    }

}
