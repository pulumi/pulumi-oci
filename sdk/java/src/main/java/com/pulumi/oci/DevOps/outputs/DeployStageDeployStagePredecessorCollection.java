// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.DeployStageDeployStagePredecessorCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class DeployStageDeployStagePredecessorCollection {
    /**
     * @return (Updatable) The IP address of the backend server. A server could be a compute instance or a load balancer.
     * 
     */
    private final List<DeployStageDeployStagePredecessorCollectionItem> items;

    @CustomType.Constructor
    private DeployStageDeployStagePredecessorCollection(@CustomType.Parameter("items") List<DeployStageDeployStagePredecessorCollectionItem> items) {
        this.items = items;
    }

    /**
     * @return (Updatable) The IP address of the backend server. A server could be a compute instance or a load balancer.
     * 
     */
    public List<DeployStageDeployStagePredecessorCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeployStageDeployStagePredecessorCollection defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<DeployStageDeployStagePredecessorCollectionItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(DeployStageDeployStagePredecessorCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<DeployStageDeployStagePredecessorCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(DeployStageDeployStagePredecessorCollectionItem... items) {
            return items(List.of(items));
        }        public DeployStageDeployStagePredecessorCollection build() {
            return new DeployStageDeployStagePredecessorCollection(items);
        }
    }
}
