// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiDocument.outputs.ProcessorJobProcessorConfigFeature;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ProcessorJobProcessorConfig {
    /**
     * @return The document type.
     * 
     */
    private @Nullable String documentType;
    /**
     * @return The types of document analysis requested.
     * 
     */
    private List<ProcessorJobProcessorConfigFeature> features;
    /**
     * @return Whether or not to generate a ZIP file containing the results.
     * 
     */
    private @Nullable Boolean isZipOutputEnabled;
    /**
     * @return The document language, abbreviated according to the BCP 47 Language-Tag syntax.
     * 
     */
    private @Nullable String language;
    /**
     * @return The type of the processor.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private String processorType;

    private ProcessorJobProcessorConfig() {}
    /**
     * @return The document type.
     * 
     */
    public Optional<String> documentType() {
        return Optional.ofNullable(this.documentType);
    }
    /**
     * @return The types of document analysis requested.
     * 
     */
    public List<ProcessorJobProcessorConfigFeature> features() {
        return this.features;
    }
    /**
     * @return Whether or not to generate a ZIP file containing the results.
     * 
     */
    public Optional<Boolean> isZipOutputEnabled() {
        return Optional.ofNullable(this.isZipOutputEnabled);
    }
    /**
     * @return The document language, abbreviated according to the BCP 47 Language-Tag syntax.
     * 
     */
    public Optional<String> language() {
        return Optional.ofNullable(this.language);
    }
    /**
     * @return The type of the processor.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public String processorType() {
        return this.processorType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ProcessorJobProcessorConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String documentType;
        private List<ProcessorJobProcessorConfigFeature> features;
        private @Nullable Boolean isZipOutputEnabled;
        private @Nullable String language;
        private String processorType;
        public Builder() {}
        public Builder(ProcessorJobProcessorConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.documentType = defaults.documentType;
    	      this.features = defaults.features;
    	      this.isZipOutputEnabled = defaults.isZipOutputEnabled;
    	      this.language = defaults.language;
    	      this.processorType = defaults.processorType;
        }

        @CustomType.Setter
        public Builder documentType(@Nullable String documentType) {

            this.documentType = documentType;
            return this;
        }
        @CustomType.Setter
        public Builder features(List<ProcessorJobProcessorConfigFeature> features) {
            if (features == null) {
              throw new MissingRequiredPropertyException("ProcessorJobProcessorConfig", "features");
            }
            this.features = features;
            return this;
        }
        public Builder features(ProcessorJobProcessorConfigFeature... features) {
            return features(List.of(features));
        }
        @CustomType.Setter
        public Builder isZipOutputEnabled(@Nullable Boolean isZipOutputEnabled) {

            this.isZipOutputEnabled = isZipOutputEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder language(@Nullable String language) {

            this.language = language;
            return this;
        }
        @CustomType.Setter
        public Builder processorType(String processorType) {
            if (processorType == null) {
              throw new MissingRequiredPropertyException("ProcessorJobProcessorConfig", "processorType");
            }
            this.processorType = processorType;
            return this;
        }
        public ProcessorJobProcessorConfig build() {
            final var _resultValue = new ProcessorJobProcessorConfig();
            _resultValue.documentType = documentType;
            _resultValue.features = features;
            _resultValue.isZipOutputEnabled = isZipOutputEnabled;
            _resultValue.language = language;
            _resultValue.processorType = processorType;
            return _resultValue;
        }
    }
}
