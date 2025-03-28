// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetModelsModelCollectionItemModelDetailClassificationMode {
    /**
     * @return classification Modes
     * 
     */
    private String classificationMode;
    /**
     * @return For pre trained models this will identify model type version used for model creation For custom identifying the model by model id is difficult. This param provides ease of use for end customer. &lt;&lt;service&gt;&gt;::&lt;&lt;service-name&gt;&gt;_&lt;&lt;model-type-version&gt;&gt;::&lt;&lt;custom model on which this training has to be done&gt;&gt; ex: ai-lang::NER_V1::CUSTOM-V0
     * 
     */
    private String version;

    private GetModelsModelCollectionItemModelDetailClassificationMode() {}
    /**
     * @return classification Modes
     * 
     */
    public String classificationMode() {
        return this.classificationMode;
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

    public static Builder builder(GetModelsModelCollectionItemModelDetailClassificationMode defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String classificationMode;
        private String version;
        public Builder() {}
        public Builder(GetModelsModelCollectionItemModelDetailClassificationMode defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.classificationMode = defaults.classificationMode;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder classificationMode(String classificationMode) {
            if (classificationMode == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemModelDetailClassificationMode", "classificationMode");
            }
            this.classificationMode = classificationMode;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemModelDetailClassificationMode", "version");
            }
            this.version = version;
            return this;
        }
        public GetModelsModelCollectionItemModelDetailClassificationMode build() {
            final var _resultValue = new GetModelsModelCollectionItemModelDetailClassificationMode();
            _resultValue.classificationMode = classificationMode;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
