// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeployStageDeployStagePredecessorCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployStageDeployStagePredecessorCollection {
    /**
     * @return The IP address of the backend server. A server could be a compute instance or a load balancer.
     * 
     */
    private final List<GetDeployStageDeployStagePredecessorCollectionItem> items;

    @CustomType.Constructor
    private GetDeployStageDeployStagePredecessorCollection(@CustomType.Parameter("items") List<GetDeployStageDeployStagePredecessorCollectionItem> items) {
        this.items = items;
    }

    /**
     * @return The IP address of the backend server. A server could be a compute instance or a load balancer.
     * 
     */
    public List<GetDeployStageDeployStagePredecessorCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployStageDeployStagePredecessorCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDeployStageDeployStagePredecessorCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeployStageDeployStagePredecessorCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetDeployStageDeployStagePredecessorCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDeployStageDeployStagePredecessorCollectionItem... items) {
            return items(List.of(items));
        }        public GetDeployStageDeployStagePredecessorCollection build() {
            return new GetDeployStageDeployStagePredecessorCollection(items);
        }
    }
}
