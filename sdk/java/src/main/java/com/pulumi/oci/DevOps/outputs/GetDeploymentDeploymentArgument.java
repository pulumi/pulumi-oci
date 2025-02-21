// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.outputs.GetDeploymentDeploymentArgumentItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentDeploymentArgument {
    /**
     * @return A list of stage predecessors for a stage.
     * 
     */
    private List<GetDeploymentDeploymentArgumentItem> items;

    private GetDeploymentDeploymentArgument() {}
    /**
     * @return A list of stage predecessors for a stage.
     * 
     */
    public List<GetDeploymentDeploymentArgumentItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentDeploymentArgument defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentDeploymentArgumentItem> items;
        public Builder() {}
        public Builder(GetDeploymentDeploymentArgument defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDeploymentDeploymentArgumentItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDeploymentDeploymentArgument", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDeploymentDeploymentArgumentItem... items) {
            return items(List.of(items));
        }
        public GetDeploymentDeploymentArgument build() {
            final var _resultValue = new GetDeploymentDeploymentArgument();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
