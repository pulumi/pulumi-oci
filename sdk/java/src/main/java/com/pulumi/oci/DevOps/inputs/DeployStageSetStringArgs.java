// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.DeployStageSetStringItemArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeployStageSetStringArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployStageSetStringArgs Empty = new DeployStageSetStringArgs();

    /**
     * (Updatable) List of parameters defined to set helm value.
     * 
     */
    @Import(name="items")
    private @Nullable Output<List<DeployStageSetStringItemArgs>> items;

    /**
     * @return (Updatable) List of parameters defined to set helm value.
     * 
     */
    public Optional<Output<List<DeployStageSetStringItemArgs>>> items() {
        return Optional.ofNullable(this.items);
    }

    private DeployStageSetStringArgs() {}

    private DeployStageSetStringArgs(DeployStageSetStringArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployStageSetStringArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployStageSetStringArgs $;

        public Builder() {
            $ = new DeployStageSetStringArgs();
        }

        public Builder(DeployStageSetStringArgs defaults) {
            $ = new DeployStageSetStringArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items (Updatable) List of parameters defined to set helm value.
         * 
         * @return builder
         * 
         */
        public Builder items(@Nullable Output<List<DeployStageSetStringItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items (Updatable) List of parameters defined to set helm value.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DeployStageSetStringItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items (Updatable) List of parameters defined to set helm value.
         * 
         * @return builder
         * 
         */
        public Builder items(DeployStageSetStringItemArgs... items) {
            return items(List.of(items));
        }

        public DeployStageSetStringArgs build() {
            return $;
        }
    }

}