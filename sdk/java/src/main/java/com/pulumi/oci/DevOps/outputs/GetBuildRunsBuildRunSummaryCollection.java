// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetBuildRunsBuildRunSummaryCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBuildRunsBuildRunSummaryCollection {
    /**
     * @return List of exported variables.
     * 
     */
    private List<GetBuildRunsBuildRunSummaryCollectionItem> items;

    private GetBuildRunsBuildRunSummaryCollection() {}
    /**
     * @return List of exported variables.
     * 
     */
    public List<GetBuildRunsBuildRunSummaryCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildRunsBuildRunSummaryCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetBuildRunsBuildRunSummaryCollectionItem> items;
        public Builder() {}
        public Builder(GetBuildRunsBuildRunSummaryCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetBuildRunsBuildRunSummaryCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetBuildRunsBuildRunSummaryCollectionItem... items) {
            return items(List.of(items));
        }
        public GetBuildRunsBuildRunSummaryCollection build() {
            final var o = new GetBuildRunsBuildRunSummaryCollection();
            o.items = items;
            return o;
        }
    }
}