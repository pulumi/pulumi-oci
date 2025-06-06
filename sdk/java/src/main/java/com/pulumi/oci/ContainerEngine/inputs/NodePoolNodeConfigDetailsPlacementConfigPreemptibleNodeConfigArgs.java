// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ContainerEngine.inputs.NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigPreemptionActionArgs;
import java.util.Objects;


public final class NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs Empty = new NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs();

    /**
     * (Updatable) The action to run when the preemptible node is interrupted for eviction.
     * 
     */
    @Import(name="preemptionAction", required=true)
    private Output<NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigPreemptionActionArgs> preemptionAction;

    /**
     * @return (Updatable) The action to run when the preemptible node is interrupted for eviction.
     * 
     */
    public Output<NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigPreemptionActionArgs> preemptionAction() {
        return this.preemptionAction;
    }

    private NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs() {}

    private NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs(NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs $) {
        this.preemptionAction = $.preemptionAction;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs $;

        public Builder() {
            $ = new NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs();
        }

        public Builder(NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs defaults) {
            $ = new NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param preemptionAction (Updatable) The action to run when the preemptible node is interrupted for eviction.
         * 
         * @return builder
         * 
         */
        public Builder preemptionAction(Output<NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigPreemptionActionArgs> preemptionAction) {
            $.preemptionAction = preemptionAction;
            return this;
        }

        /**
         * @param preemptionAction (Updatable) The action to run when the preemptible node is interrupted for eviction.
         * 
         * @return builder
         * 
         */
        public Builder preemptionAction(NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigPreemptionActionArgs preemptionAction) {
            return preemptionAction(Output.of(preemptionAction));
        }

        public NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs build() {
            if ($.preemptionAction == null) {
                throw new MissingRequiredPropertyException("NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigArgs", "preemptionAction");
            }
            return $;
        }
    }

}
