// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetBuildRunsBuildRunSummaryCollectionItemBuildRunArgumentsItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBuildRunsBuildRunSummaryCollectionItemBuildRunArguments {
    /**
     * @return List of exported variables.
     * 
     */
    private List<GetBuildRunsBuildRunSummaryCollectionItemBuildRunArgumentsItem> items;

    private GetBuildRunsBuildRunSummaryCollectionItemBuildRunArguments() {}
    /**
     * @return List of exported variables.
     * 
     */
    public List<GetBuildRunsBuildRunSummaryCollectionItemBuildRunArgumentsItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildRunsBuildRunSummaryCollectionItemBuildRunArguments defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetBuildRunsBuildRunSummaryCollectionItemBuildRunArgumentsItem> items;
        public Builder() {}
        public Builder(GetBuildRunsBuildRunSummaryCollectionItemBuildRunArguments defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetBuildRunsBuildRunSummaryCollectionItemBuildRunArgumentsItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetBuildRunsBuildRunSummaryCollectionItemBuildRunArgumentsItem... items) {
            return items(List.of(items));
        }
        public GetBuildRunsBuildRunSummaryCollectionItemBuildRunArguments build() {
            final var o = new GetBuildRunsBuildRunSummaryCollectionItemBuildRunArguments();
            o.items = items;
            return o;
        }
    }
}