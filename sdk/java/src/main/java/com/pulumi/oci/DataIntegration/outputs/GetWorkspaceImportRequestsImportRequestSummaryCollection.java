// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceImportRequestsImportRequestSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWorkspaceImportRequestsImportRequestSummaryCollection {
    private List<GetWorkspaceImportRequestsImportRequestSummaryCollectionItem> items;

    private GetWorkspaceImportRequestsImportRequestSummaryCollection() {}
    public List<GetWorkspaceImportRequestsImportRequestSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceImportRequestsImportRequestSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWorkspaceImportRequestsImportRequestSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetWorkspaceImportRequestsImportRequestSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetWorkspaceImportRequestsImportRequestSummaryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetWorkspaceImportRequestsImportRequestSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetWorkspaceImportRequestsImportRequestSummaryCollection build() {
            final var o = new GetWorkspaceImportRequestsImportRequestSummaryCollection();
            o.items = items;
            return o;
        }
    }
}