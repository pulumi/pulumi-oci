// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceFoldersFolderSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWorkspaceFoldersFolderSummaryCollection {
    private List<GetWorkspaceFoldersFolderSummaryCollectionItem> items;

    private GetWorkspaceFoldersFolderSummaryCollection() {}
    public List<GetWorkspaceFoldersFolderSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceFoldersFolderSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWorkspaceFoldersFolderSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetWorkspaceFoldersFolderSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetWorkspaceFoldersFolderSummaryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetWorkspaceFoldersFolderSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetWorkspaceFoldersFolderSummaryCollection build() {
            final var o = new GetWorkspaceFoldersFolderSummaryCollection();
            o.items = items;
            return o;
        }
    }
}