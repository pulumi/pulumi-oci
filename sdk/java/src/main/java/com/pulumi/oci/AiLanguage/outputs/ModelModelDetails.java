// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.AiLanguage.outputs.ModelModelDetailsClassificationMode;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ModelModelDetails {
    /**
     * @return classification Modes
     * 
     */
    private @Nullable ModelModelDetailsClassificationMode classificationMode;
    /**
     * @return supported language default value is en
     * 
     */
    private @Nullable String languageCode;
    /**
     * @return Model type
     * 
     */
    private String modelType;
    /**
     * @return Optional pre trained model version. if nothing specified latest pre trained model will be used.  Supported versions can be found at /modelTypes/{modelType}
     * 
     */
    private @Nullable String version;

    private ModelModelDetails() {}
    /**
     * @return classification Modes
     * 
     */
    public Optional<ModelModelDetailsClassificationMode> classificationMode() {
        return Optional.ofNullable(this.classificationMode);
    }
    /**
     * @return supported language default value is en
     * 
     */
    public Optional<String> languageCode() {
        return Optional.ofNullable(this.languageCode);
    }
    /**
     * @return Model type
     * 
     */
    public String modelType() {
        return this.modelType;
    }
    /**
     * @return Optional pre trained model version. if nothing specified latest pre trained model will be used.  Supported versions can be found at /modelTypes/{modelType}
     * 
     */
    public Optional<String> version() {
        return Optional.ofNullable(this.version);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ModelModelDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable ModelModelDetailsClassificationMode classificationMode;
        private @Nullable String languageCode;
        private String modelType;
        private @Nullable String version;
        public Builder() {}
        public Builder(ModelModelDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.classificationMode = defaults.classificationMode;
    	      this.languageCode = defaults.languageCode;
    	      this.modelType = defaults.modelType;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder classificationMode(@Nullable ModelModelDetailsClassificationMode classificationMode) {
            this.classificationMode = classificationMode;
            return this;
        }
        @CustomType.Setter
        public Builder languageCode(@Nullable String languageCode) {
            this.languageCode = languageCode;
            return this;
        }
        @CustomType.Setter
        public Builder modelType(String modelType) {
            this.modelType = Objects.requireNonNull(modelType);
            return this;
        }
        @CustomType.Setter
        public Builder version(@Nullable String version) {
            this.version = version;
            return this;
        }
        public ModelModelDetails build() {
            final var o = new ModelModelDetails();
            o.classificationMode = classificationMode;
            o.languageCode = languageCode;
            o.modelType = modelType;
            o.version = version;
            return o;
        }
    }
}