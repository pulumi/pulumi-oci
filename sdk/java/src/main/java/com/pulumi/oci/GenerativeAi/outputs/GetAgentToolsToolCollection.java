// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GenerativeAi.outputs.GetAgentToolsToolCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAgentToolsToolCollection {
    private List<GetAgentToolsToolCollectionItem> items;

    private GetAgentToolsToolCollection() {}
    public List<GetAgentToolsToolCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAgentToolsToolCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAgentToolsToolCollectionItem> items;
        public Builder() {}
        public Builder(GetAgentToolsToolCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetAgentToolsToolCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetAgentToolsToolCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetAgentToolsToolCollectionItem... items) {
            return items(List.of(items));
        }
        public GetAgentToolsToolCollection build() {
            final var _resultValue = new GetAgentToolsToolCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
