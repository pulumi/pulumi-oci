// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Functions.outputs.GetPbfListingVersionsPbfListingVersionsCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetPbfListingVersionsPbfListingVersionsCollection {
    /**
     * @return List of PbfListingVersionSummary.
     * 
     */
    private List<GetPbfListingVersionsPbfListingVersionsCollectionItem> items;

    private GetPbfListingVersionsPbfListingVersionsCollection() {}
    /**
     * @return List of PbfListingVersionSummary.
     * 
     */
    public List<GetPbfListingVersionsPbfListingVersionsCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPbfListingVersionsPbfListingVersionsCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetPbfListingVersionsPbfListingVersionsCollectionItem> items;
        public Builder() {}
        public Builder(GetPbfListingVersionsPbfListingVersionsCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetPbfListingVersionsPbfListingVersionsCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetPbfListingVersionsPbfListingVersionsCollectionItem... items) {
            return items(List.of(items));
        }
        public GetPbfListingVersionsPbfListingVersionsCollection build() {
            final var o = new GetPbfListingVersionsPbfListingVersionsCollection();
            o.items = items;
            return o;
        }
    }
}