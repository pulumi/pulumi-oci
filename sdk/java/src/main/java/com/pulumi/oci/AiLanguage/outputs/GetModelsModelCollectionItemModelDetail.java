// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.AiLanguage.outputs.GetModelsModelCollectionItemModelDetailClassificationMode;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetModelsModelCollectionItemModelDetail {
    /**
     * @return classification Modes
     * 
     */
    private List<GetModelsModelCollectionItemModelDetailClassificationMode> classificationModes;
    /**
     * @return supported language default value is en
     * 
     */
    private String languageCode;
    /**
     * @return Model type
     * 
     */
    private String modelType;
    /**
     * @return For pre trained models this will identify model type version used for model creation For custom identifying the model by model id is difficult. This param provides ease of use for end customer. &lt;&lt;service&gt;&gt;::&lt;&lt;service-name&gt;&gt;_&lt;&lt;model-type-version&gt;&gt;::&lt;&lt;custom model on which this training has to be done&gt;&gt; ex: ai-lang::NER_V1::CUSTOM-V0
     * 
     */
    private String version;

    private GetModelsModelCollectionItemModelDetail() {}
    /**
     * @return classification Modes
     * 
     */
    public List<GetModelsModelCollectionItemModelDetailClassificationMode> classificationModes() {
        return this.classificationModes;
    }
    /**
     * @return supported language default value is en
     * 
     */
    public String languageCode() {
        return this.languageCode;
    }
    /**
     * @return Model type
     * 
     */
    public String modelType() {
        return this.modelType;
    }
    /**
     * @return For pre trained models this will identify model type version used for model creation For custom identifying the model by model id is difficult. This param provides ease of use for end customer. &lt;&lt;service&gt;&gt;::&lt;&lt;service-name&gt;&gt;_&lt;&lt;model-type-version&gt;&gt;::&lt;&lt;custom model on which this training has to be done&gt;&gt; ex: ai-lang::NER_V1::CUSTOM-V0
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelsModelCollectionItemModelDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetModelsModelCollectionItemModelDetailClassificationMode> classificationModes;
        private String languageCode;
        private String modelType;
        private String version;
        public Builder() {}
        public Builder(GetModelsModelCollectionItemModelDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.classificationModes = defaults.classificationModes;
    	      this.languageCode = defaults.languageCode;
    	      this.modelType = defaults.modelType;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder classificationModes(List<GetModelsModelCollectionItemModelDetailClassificationMode> classificationModes) {
            this.classificationModes = Objects.requireNonNull(classificationModes);
            return this;
        }
        public Builder classificationModes(GetModelsModelCollectionItemModelDetailClassificationMode... classificationModes) {
            return classificationModes(List.of(classificationModes));
        }
        @CustomType.Setter
        public Builder languageCode(String languageCode) {
            this.languageCode = Objects.requireNonNull(languageCode);
            return this;
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            this.modelType = Objects.requireNonNull(modelType);
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }
        public GetModelsModelCollectionItemModelDetail build() {
            final var o = new GetModelsModelCollectionItemModelDetail();
            o.classificationModes = classificationModes;
            o.languageCode = languageCode;
            o.modelType = modelType;
            o.version = version;
            return o;
        }
    }
}