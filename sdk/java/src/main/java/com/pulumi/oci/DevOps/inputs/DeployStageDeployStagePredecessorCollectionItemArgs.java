// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class DeployStageDeployStagePredecessorCollectionItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployStageDeployStagePredecessorCollectionItemArgs Empty = new DeployStageDeployStagePredecessorCollectionItemArgs();

    /**
     * (Updatable) The OCID of the predecessor stage. If a stage is the first stage in the pipeline, then the ID is the pipeline&#39;s OCID.
     * 
     */
    @Import(name="id", required=true)
    private Output<String> id;

    /**
     * @return (Updatable) The OCID of the predecessor stage. If a stage is the first stage in the pipeline, then the ID is the pipeline&#39;s OCID.
     * 
     */
    public Output<String> id() {
        return this.id;
    }

    private DeployStageDeployStagePredecessorCollectionItemArgs() {}

    private DeployStageDeployStagePredecessorCollectionItemArgs(DeployStageDeployStagePredecessorCollectionItemArgs $) {
        this.id = $.id;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployStageDeployStagePredecessorCollectionItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployStageDeployStagePredecessorCollectionItemArgs $;

        public Builder() {
            $ = new DeployStageDeployStagePredecessorCollectionItemArgs();
        }

        public Builder(DeployStageDeployStagePredecessorCollectionItemArgs defaults) {
            $ = new DeployStageDeployStagePredecessorCollectionItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param id (Updatable) The OCID of the predecessor stage. If a stage is the first stage in the pipeline, then the ID is the pipeline&#39;s OCID.
         * 
         * @return builder
         * 
         */
        public Builder id(Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id (Updatable) The OCID of the predecessor stage. If a stage is the first stage in the pipeline, then the ID is the pipeline&#39;s OCID.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        public DeployStageDeployStagePredecessorCollectionItemArgs build() {
            $.id = Objects.requireNonNull($.id, "expected parameter 'id' to be non-null");
            return $;
        }
    }

}