// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetDeployStageArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDeployStageArgs Empty = new GetDeployStageArgs();

    /**
     * Unique stage identifier.
     * 
     */
    @Import(name="deployStageId", required=true)
    private Output<String> deployStageId;

    /**
     * @return Unique stage identifier.
     * 
     */
    public Output<String> deployStageId() {
        return this.deployStageId;
    }

    private GetDeployStageArgs() {}

    private GetDeployStageArgs(GetDeployStageArgs $) {
        this.deployStageId = $.deployStageId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDeployStageArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDeployStageArgs $;

        public Builder() {
            $ = new GetDeployStageArgs();
        }

        public Builder(GetDeployStageArgs defaults) {
            $ = new GetDeployStageArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param deployStageId Unique stage identifier.
         * 
         * @return builder
         * 
         */
        public Builder deployStageId(Output<String> deployStageId) {
            $.deployStageId = deployStageId;
            return this;
        }

        /**
         * @param deployStageId Unique stage identifier.
         * 
         * @return builder
         * 
         */
        public Builder deployStageId(String deployStageId) {
            return deployStageId(Output.of(deployStageId));
        }

        public GetDeployStageArgs build() {
            $.deployStageId = Objects.requireNonNull($.deployStageId, "expected parameter 'deployStageId' to be non-null");
            return $;
        }
    }

}