// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetModelsModelCollectionItemComponentModel {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of active custom Key Value model that need to be composed.
     * 
     */
    private String modelId;

    private GetModelsModelCollectionItemComponentModel() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of active custom Key Value model that need to be composed.
     * 
     */
    public String modelId() {
        return this.modelId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelsModelCollectionItemComponentModel defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String modelId;
        public Builder() {}
        public Builder(GetModelsModelCollectionItemComponentModel defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.modelId = defaults.modelId;
        }

        @CustomType.Setter
        public Builder modelId(String modelId) {
            this.modelId = Objects.requireNonNull(modelId);
            return this;
        }
        public GetModelsModelCollectionItemComponentModel build() {
            final var o = new GetModelsModelCollectionItemComponentModel();
            o.modelId = modelId;
            return o;
        }
    }
}