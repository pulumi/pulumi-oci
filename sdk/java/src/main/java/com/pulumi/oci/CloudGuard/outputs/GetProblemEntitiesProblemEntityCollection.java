// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetProblemEntitiesProblemEntityCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetProblemEntitiesProblemEntityCollection {
    /**
     * @return List of problem entities summaries related to a data source.
     * 
     */
    private List<GetProblemEntitiesProblemEntityCollectionItem> items;

    private GetProblemEntitiesProblemEntityCollection() {}
    /**
     * @return List of problem entities summaries related to a data source.
     * 
     */
    public List<GetProblemEntitiesProblemEntityCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProblemEntitiesProblemEntityCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetProblemEntitiesProblemEntityCollectionItem> items;
        public Builder() {}
        public Builder(GetProblemEntitiesProblemEntityCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetProblemEntitiesProblemEntityCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetProblemEntitiesProblemEntityCollectionItem... items) {
            return items(List.of(items));
        }
        public GetProblemEntitiesProblemEntityCollection build() {
            final var o = new GetProblemEntitiesProblemEntityCollection();
            o.items = items;
            return o;
        }
    }
}