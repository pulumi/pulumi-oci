// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetProcessorJobProcessorConfigFeature {
    /**
     * @return The type of document analysis requested. The allowed values are:
     * * `LANGUAGE_CLASSIFICATION`: Detect the language.
     * * `TEXT_EXTRACTION`: Recognize text.
     * * `TABLE_EXTRACTION`: Detect and extract data in tables.
     * * `KEY_VALUE_EXTRACTION`: Extract form fields.
     * * `DOCUMENT_CLASSIFICATION`: Identify the type of document.
     * 
     */
    private String featureType;
    /**
     * @return Whether or not to generate a searchable PDF file.
     * 
     */
    private Boolean generateSearchablePdf;
    /**
     * @return The maximum number of results to return.
     * 
     */
    private Integer maxResults;
    /**
     * @return The custom model ID.
     * 
     */
    private String modelId;
    /**
     * @return The custom model tenancy ID when modelId represents aliasName.
     * 
     */
    private String tenancyId;

    private GetProcessorJobProcessorConfigFeature() {}
    /**
     * @return The type of document analysis requested. The allowed values are:
     * * `LANGUAGE_CLASSIFICATION`: Detect the language.
     * * `TEXT_EXTRACTION`: Recognize text.
     * * `TABLE_EXTRACTION`: Detect and extract data in tables.
     * * `KEY_VALUE_EXTRACTION`: Extract form fields.
     * * `DOCUMENT_CLASSIFICATION`: Identify the type of document.
     * 
     */
    public String featureType() {
        return this.featureType;
    }
    /**
     * @return Whether or not to generate a searchable PDF file.
     * 
     */
    public Boolean generateSearchablePdf() {
        return this.generateSearchablePdf;
    }
    /**
     * @return The maximum number of results to return.
     * 
     */
    public Integer maxResults() {
        return this.maxResults;
    }
    /**
     * @return The custom model ID.
     * 
     */
    public String modelId() {
        return this.modelId;
    }
    /**
     * @return The custom model tenancy ID when modelId represents aliasName.
     * 
     */
    public String tenancyId() {
        return this.tenancyId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProcessorJobProcessorConfigFeature defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String featureType;
        private Boolean generateSearchablePdf;
        private Integer maxResults;
        private String modelId;
        private String tenancyId;
        public Builder() {}
        public Builder(GetProcessorJobProcessorConfigFeature defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.featureType = defaults.featureType;
    	      this.generateSearchablePdf = defaults.generateSearchablePdf;
    	      this.maxResults = defaults.maxResults;
    	      this.modelId = defaults.modelId;
    	      this.tenancyId = defaults.tenancyId;
        }

        @CustomType.Setter
        public Builder featureType(String featureType) {
            if (featureType == null) {
              throw new MissingRequiredPropertyException("GetProcessorJobProcessorConfigFeature", "featureType");
            }
            this.featureType = featureType;
            return this;
        }
        @CustomType.Setter
        public Builder generateSearchablePdf(Boolean generateSearchablePdf) {
            if (generateSearchablePdf == null) {
              throw new MissingRequiredPropertyException("GetProcessorJobProcessorConfigFeature", "generateSearchablePdf");
            }
            this.generateSearchablePdf = generateSearchablePdf;
            return this;
        }
        @CustomType.Setter
        public Builder maxResults(Integer maxResults) {
            if (maxResults == null) {
              throw new MissingRequiredPropertyException("GetProcessorJobProcessorConfigFeature", "maxResults");
            }
            this.maxResults = maxResults;
            return this;
        }
        @CustomType.Setter
        public Builder modelId(String modelId) {
            if (modelId == null) {
              throw new MissingRequiredPropertyException("GetProcessorJobProcessorConfigFeature", "modelId");
            }
            this.modelId = modelId;
            return this;
        }
        @CustomType.Setter
        public Builder tenancyId(String tenancyId) {
            if (tenancyId == null) {
              throw new MissingRequiredPropertyException("GetProcessorJobProcessorConfigFeature", "tenancyId");
            }
            this.tenancyId = tenancyId;
            return this;
        }
        public GetProcessorJobProcessorConfigFeature build() {
            final var _resultValue = new GetProcessorJobProcessorConfigFeature();
            _resultValue.featureType = featureType;
            _resultValue.generateSearchablePdf = generateSearchablePdf;
            _resultValue.maxResults = maxResults;
            _resultValue.modelId = modelId;
            _resultValue.tenancyId = tenancyId;
            return _resultValue;
        }
    }
}
