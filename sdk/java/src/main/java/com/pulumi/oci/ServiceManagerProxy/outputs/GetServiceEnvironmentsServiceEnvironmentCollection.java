// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceManagerProxy.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ServiceManagerProxy.outputs.GetServiceEnvironmentsServiceEnvironmentCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetServiceEnvironmentsServiceEnvironmentCollection {
    private final List<GetServiceEnvironmentsServiceEnvironmentCollectionItem> items;

    @CustomType.Constructor
    private GetServiceEnvironmentsServiceEnvironmentCollection(@CustomType.Parameter("items") List<GetServiceEnvironmentsServiceEnvironmentCollectionItem> items) {
        this.items = items;
    }

    public List<GetServiceEnvironmentsServiceEnvironmentCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceEnvironmentsServiceEnvironmentCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetServiceEnvironmentsServiceEnvironmentCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetServiceEnvironmentsServiceEnvironmentCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetServiceEnvironmentsServiceEnvironmentCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetServiceEnvironmentsServiceEnvironmentCollectionItem... items) {
            return items(List.of(items));
        }        public GetServiceEnvironmentsServiceEnvironmentCollection build() {
            return new GetServiceEnvironmentsServiceEnvironmentCollection(items);
        }
    }
}
