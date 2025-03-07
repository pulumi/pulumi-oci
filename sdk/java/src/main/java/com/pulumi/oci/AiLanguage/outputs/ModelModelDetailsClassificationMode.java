// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ModelModelDetailsClassificationMode {
    /**
     * @return classification Modes
     * 
     */
    private String classificationMode;
    /**
     * @return Optional if nothing specified latest base model will be used for training. Supported versions can be found at /modelTypes/{modelType}
     * 
     */
    private @Nullable String version;

    private ModelModelDetailsClassificationMode() {}
    /**
     * @return classification Modes
     * 
     */
    public String classificationMode() {
        return this.classificationMode;
    }
    /**
     * @return Optional if nothing specified latest base model will be used for training. Supported versions can be found at /modelTypes/{modelType}
     * 
     */
    public Optional<String> version() {
        return Optional.ofNullable(this.version);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ModelModelDetailsClassificationMode defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String classificationMode;
        private @Nullable String version;
        public Builder() {}
        public Builder(ModelModelDetailsClassificationMode defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.classificationMode = defaults.classificationMode;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder classificationMode(String classificationMode) {
            if (classificationMode == null) {
              throw new MissingRequiredPropertyException("ModelModelDetailsClassificationMode", "classificationMode");
            }
            this.classificationMode = classificationMode;
            return this;
        }
        @CustomType.Setter
        public Builder version(@Nullable String version) {

            this.version = version;
            return this;
        }
        public ModelModelDetailsClassificationMode build() {
            final var _resultValue = new ModelModelDetailsClassificationMode();
            _resultValue.classificationMode = classificationMode;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
