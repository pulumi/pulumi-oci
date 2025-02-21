// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ModelComponentModel {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of active custom Key Value model that need to be composed.
     * 
     */
    private @Nullable String modelId;

    private ModelComponentModel() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of active custom Key Value model that need to be composed.
     * 
     */
    public Optional<String> modelId() {
        return Optional.ofNullable(this.modelId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ModelComponentModel defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String modelId;
        public Builder() {}
        public Builder(ModelComponentModel defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.modelId = defaults.modelId;
        }

        @CustomType.Setter
        public Builder modelId(@Nullable String modelId) {

            this.modelId = modelId;
            return this;
        }
        public ModelComponentModel build() {
            final var _resultValue = new ModelComponentModel();
            _resultValue.modelId = modelId;
            return _resultValue;
        }
    }
}
