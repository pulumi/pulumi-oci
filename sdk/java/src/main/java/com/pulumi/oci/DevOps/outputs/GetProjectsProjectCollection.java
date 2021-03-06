// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetProjectsProjectCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetProjectsProjectCollection {
    private final List<GetProjectsProjectCollectionItem> items;

    @CustomType.Constructor
    private GetProjectsProjectCollection(@CustomType.Parameter("items") List<GetProjectsProjectCollectionItem> items) {
        this.items = items;
    }

    public List<GetProjectsProjectCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProjectsProjectCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetProjectsProjectCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetProjectsProjectCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetProjectsProjectCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetProjectsProjectCollectionItem... items) {
            return items(List.of(items));
        }        public GetProjectsProjectCollection build() {
            return new GetProjectsProjectCollection(items);
        }
    }
}
