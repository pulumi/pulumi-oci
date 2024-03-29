// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDeployArtifactArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDeployArtifactArgs Empty = new GetDeployArtifactArgs();

    /**
     * Unique artifact identifier.
     * 
     */
    @Import(name="deployArtifactId", required=true)
    private Output<String> deployArtifactId;

    /**
     * @return Unique artifact identifier.
     * 
     */
    public Output<String> deployArtifactId() {
        return this.deployArtifactId;
    }

    private GetDeployArtifactArgs() {}

    private GetDeployArtifactArgs(GetDeployArtifactArgs $) {
        this.deployArtifactId = $.deployArtifactId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDeployArtifactArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDeployArtifactArgs $;

        public Builder() {
            $ = new GetDeployArtifactArgs();
        }

        public Builder(GetDeployArtifactArgs defaults) {
            $ = new GetDeployArtifactArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param deployArtifactId Unique artifact identifier.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactId(Output<String> deployArtifactId) {
            $.deployArtifactId = deployArtifactId;
            return this;
        }

        /**
         * @param deployArtifactId Unique artifact identifier.
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactId(String deployArtifactId) {
            return deployArtifactId(Output.of(deployArtifactId));
        }

        public GetDeployArtifactArgs build() {
            if ($.deployArtifactId == null) {
                throw new MissingRequiredPropertyException("GetDeployArtifactArgs", "deployArtifactId");
            }
            return $;
        }
    }

}
