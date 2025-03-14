// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.outputs.GetDeployStageSetValueItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployStageSetValue {
    /**
     * @return List of parameters defined to set helm value.
     * 
     */
    private List<GetDeployStageSetValueItem> items;

    private GetDeployStageSetValue() {}
    /**
     * @return List of parameters defined to set helm value.
     * 
     */
    public List<GetDeployStageSetValueItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployStageSetValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeployStageSetValueItem> items;
        public Builder() {}
        public Builder(GetDeployStageSetValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDeployStageSetValueItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDeployStageSetValue", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDeployStageSetValueItem... items) {
            return items(List.of(items));
        }
        public GetDeployStageSetValue build() {
            final var _resultValue = new GetDeployStageSetValue();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
