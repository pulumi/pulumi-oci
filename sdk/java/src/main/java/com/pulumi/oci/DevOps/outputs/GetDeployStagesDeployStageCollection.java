// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeployStagesDeployStageCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployStagesDeployStageCollection {
    /**
     * @return The IP address of the backend server. A server could be a compute instance or a load balancer.
     * 
     */
    private List<GetDeployStagesDeployStageCollectionItem> items;

    private GetDeployStagesDeployStageCollection() {}
    /**
     * @return The IP address of the backend server. A server could be a compute instance or a load balancer.
     * 
     */
    public List<GetDeployStagesDeployStageCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployStagesDeployStageCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeployStagesDeployStageCollectionItem> items;
        public Builder() {}
        public Builder(GetDeployStagesDeployStageCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDeployStagesDeployStageCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDeployStagesDeployStageCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDeployStagesDeployStageCollection build() {
            final var o = new GetDeployStagesDeployStageCollection();
            o.items = items;
            return o;
        }
    }
}