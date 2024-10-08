// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GoldenGate.outputs.GetMessagesDeploymentMessagesCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMessagesDeploymentMessagesCollection {
    /**
     * @return An array of DeploymentMessages.
     * 
     */
    private List<GetMessagesDeploymentMessagesCollectionItem> items;

    private GetMessagesDeploymentMessagesCollection() {}
    /**
     * @return An array of DeploymentMessages.
     * 
     */
    public List<GetMessagesDeploymentMessagesCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMessagesDeploymentMessagesCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMessagesDeploymentMessagesCollectionItem> items;
        public Builder() {}
        public Builder(GetMessagesDeploymentMessagesCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetMessagesDeploymentMessagesCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetMessagesDeploymentMessagesCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetMessagesDeploymentMessagesCollectionItem... items) {
            return items(List.of(items));
        }
        public GetMessagesDeploymentMessagesCollection build() {
            final var _resultValue = new GetMessagesDeploymentMessagesCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
