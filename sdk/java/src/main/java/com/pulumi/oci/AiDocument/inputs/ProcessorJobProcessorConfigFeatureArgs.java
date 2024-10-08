// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ProcessorJobProcessorConfigFeatureArgs extends com.pulumi.resources.ResourceArgs {

    public static final ProcessorJobProcessorConfigFeatureArgs Empty = new ProcessorJobProcessorConfigFeatureArgs();

    /**
     * The type of document analysis requested. The allowed values are:
     * * `LANGUAGE_CLASSIFICATION`: Detect the language.
     * * `TEXT_EXTRACTION`: Recognize text.
     * * `TABLE_EXTRACTION`: Detect and extract data in tables.
     * * `KEY_VALUE_EXTRACTION`: Extract form fields.
     * * `DOCUMENT_CLASSIFICATION`: Identify the type of document.
     * 
     */
    @Import(name="featureType", required=true)
    private Output<String> featureType;

    /**
     * @return The type of document analysis requested. The allowed values are:
     * * `LANGUAGE_CLASSIFICATION`: Detect the language.
     * * `TEXT_EXTRACTION`: Recognize text.
     * * `TABLE_EXTRACTION`: Detect and extract data in tables.
     * * `KEY_VALUE_EXTRACTION`: Extract form fields.
     * * `DOCUMENT_CLASSIFICATION`: Identify the type of document.
     * 
     */
    public Output<String> featureType() {
        return this.featureType;
    }

    /**
     * Whether or not to generate a searchable PDF file.
     * 
     */
    @Import(name="generateSearchablePdf")
    private @Nullable Output<Boolean> generateSearchablePdf;

    /**
     * @return Whether or not to generate a searchable PDF file.
     * 
     */
    public Optional<Output<Boolean>> generateSearchablePdf() {
        return Optional.ofNullable(this.generateSearchablePdf);
    }

    /**
     * The maximum number of results to return.
     * 
     */
    @Import(name="maxResults")
    private @Nullable Output<Integer> maxResults;

    /**
     * @return The maximum number of results to return.
     * 
     */
    public Optional<Output<Integer>> maxResults() {
        return Optional.ofNullable(this.maxResults);
    }

    /**
     * The custom model ID.
     * 
     */
    @Import(name="modelId")
    private @Nullable Output<String> modelId;

    /**
     * @return The custom model ID.
     * 
     */
    public Optional<Output<String>> modelId() {
        return Optional.ofNullable(this.modelId);
    }

    /**
     * The custom model tenancy ID when modelId represents aliasName.
     * 
     */
    @Import(name="tenancyId")
    private @Nullable Output<String> tenancyId;

    /**
     * @return The custom model tenancy ID when modelId represents aliasName.
     * 
     */
    public Optional<Output<String>> tenancyId() {
        return Optional.ofNullable(this.tenancyId);
    }

    private ProcessorJobProcessorConfigFeatureArgs() {}

    private ProcessorJobProcessorConfigFeatureArgs(ProcessorJobProcessorConfigFeatureArgs $) {
        this.featureType = $.featureType;
        this.generateSearchablePdf = $.generateSearchablePdf;
        this.maxResults = $.maxResults;
        this.modelId = $.modelId;
        this.tenancyId = $.tenancyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ProcessorJobProcessorConfigFeatureArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ProcessorJobProcessorConfigFeatureArgs $;

        public Builder() {
            $ = new ProcessorJobProcessorConfigFeatureArgs();
        }

        public Builder(ProcessorJobProcessorConfigFeatureArgs defaults) {
            $ = new ProcessorJobProcessorConfigFeatureArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param featureType The type of document analysis requested. The allowed values are:
         * * `LANGUAGE_CLASSIFICATION`: Detect the language.
         * * `TEXT_EXTRACTION`: Recognize text.
         * * `TABLE_EXTRACTION`: Detect and extract data in tables.
         * * `KEY_VALUE_EXTRACTION`: Extract form fields.
         * * `DOCUMENT_CLASSIFICATION`: Identify the type of document.
         * 
         * @return builder
         * 
         */
        public Builder featureType(Output<String> featureType) {
            $.featureType = featureType;
            return this;
        }

        /**
         * @param featureType The type of document analysis requested. The allowed values are:
         * * `LANGUAGE_CLASSIFICATION`: Detect the language.
         * * `TEXT_EXTRACTION`: Recognize text.
         * * `TABLE_EXTRACTION`: Detect and extract data in tables.
         * * `KEY_VALUE_EXTRACTION`: Extract form fields.
         * * `DOCUMENT_CLASSIFICATION`: Identify the type of document.
         * 
         * @return builder
         * 
         */
        public Builder featureType(String featureType) {
            return featureType(Output.of(featureType));
        }

        /**
         * @param generateSearchablePdf Whether or not to generate a searchable PDF file.
         * 
         * @return builder
         * 
         */
        public Builder generateSearchablePdf(@Nullable Output<Boolean> generateSearchablePdf) {
            $.generateSearchablePdf = generateSearchablePdf;
            return this;
        }

        /**
         * @param generateSearchablePdf Whether or not to generate a searchable PDF file.
         * 
         * @return builder
         * 
         */
        public Builder generateSearchablePdf(Boolean generateSearchablePdf) {
            return generateSearchablePdf(Output.of(generateSearchablePdf));
        }

        /**
         * @param maxResults The maximum number of results to return.
         * 
         * @return builder
         * 
         */
        public Builder maxResults(@Nullable Output<Integer> maxResults) {
            $.maxResults = maxResults;
            return this;
        }

        /**
         * @param maxResults The maximum number of results to return.
         * 
         * @return builder
         * 
         */
        public Builder maxResults(Integer maxResults) {
            return maxResults(Output.of(maxResults));
        }

        /**
         * @param modelId The custom model ID.
         * 
         * @return builder
         * 
         */
        public Builder modelId(@Nullable Output<String> modelId) {
            $.modelId = modelId;
            return this;
        }

        /**
         * @param modelId The custom model ID.
         * 
         * @return builder
         * 
         */
        public Builder modelId(String modelId) {
            return modelId(Output.of(modelId));
        }

        /**
         * @param tenancyId The custom model tenancy ID when modelId represents aliasName.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(@Nullable Output<String> tenancyId) {
            $.tenancyId = tenancyId;
            return this;
        }

        /**
         * @param tenancyId The custom model tenancy ID when modelId represents aliasName.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(String tenancyId) {
            return tenancyId(Output.of(tenancyId));
        }

        public ProcessorJobProcessorConfigFeatureArgs build() {
            if ($.featureType == null) {
                throw new MissingRequiredPropertyException("ProcessorJobProcessorConfigFeatureArgs", "featureType");
            }
            return $;
        }
    }

}
