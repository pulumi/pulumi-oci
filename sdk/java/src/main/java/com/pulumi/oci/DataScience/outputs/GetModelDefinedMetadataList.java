// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetModelDefinedMetadataList {
    /**
     * @return Category of model metadata which should be null for defined metadata.For custom metadata is should be one of the following values &#34;Performance,Training Profile,Training and Validation Datasets,Training Environment,other&#34;.
     * 
     */
    private final String category;
    /**
     * @return A short description of the model.
     * 
     */
    private final String description;
    /**
     * @return Key of the model Metadata. The key can either be user defined or Oracle Cloud Infrastructure defined. List of Oracle Cloud Infrastructure defined keys:
     * * useCaseType
     * * libraryName
     * * libraryVersion
     * * estimatorClass
     * * hyperParameters
     * * testartifactresults
     * 
     */
    private final String key;
    /**
     * @return Allowed values for useCaseType: binary_classification, regression, multinomial_classification, clustering, recommender, dimensionality_reduction/representation, time_series_forecasting, anomaly_detection, topic_modeling, ner, sentiment_analysis, image_classification, object_localization, other
     * 
     */
    private final String value;

    @CustomType.Constructor
    private GetModelDefinedMetadataList(
        @CustomType.Parameter("category") String category,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("key") String key,
        @CustomType.Parameter("value") String value) {
        this.category = category;
        this.description = description;
        this.key = key;
        this.value = value;
    }

    /**
     * @return Category of model metadata which should be null for defined metadata.For custom metadata is should be one of the following values &#34;Performance,Training Profile,Training and Validation Datasets,Training Environment,other&#34;.
     * 
     */
    public String category() {
        return this.category;
    }
    /**
     * @return A short description of the model.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Key of the model Metadata. The key can either be user defined or Oracle Cloud Infrastructure defined. List of Oracle Cloud Infrastructure defined keys:
     * * useCaseType
     * * libraryName
     * * libraryVersion
     * * estimatorClass
     * * hyperParameters
     * * testartifactresults
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return Allowed values for useCaseType: binary_classification, regression, multinomial_classification, clustering, recommender, dimensionality_reduction/representation, time_series_forecasting, anomaly_detection, topic_modeling, ner, sentiment_analysis, image_classification, object_localization, other
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelDefinedMetadataList defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String category;
        private String description;
        private String key;
        private String value;

        public Builder() {
    	      // Empty
        }

        public Builder(GetModelDefinedMetadataList defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.category = defaults.category;
    	      this.description = defaults.description;
    	      this.key = defaults.key;
    	      this.value = defaults.value;
        }

        public Builder category(String category) {
            this.category = Objects.requireNonNull(category);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }        public GetModelDefinedMetadataList build() {
            return new GetModelDefinedMetadataList(category, description, key, value);
        }
    }
}
