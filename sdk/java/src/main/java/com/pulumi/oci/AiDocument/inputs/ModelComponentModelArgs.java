// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelComponentModelArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelComponentModelArgs Empty = new ModelComponentModelArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of active custom Key Value model that need to be composed.
     * 
     */
    @Import(name="modelId")
    private @Nullable Output<String> modelId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of active custom Key Value model that need to be composed.
     * 
     */
    public Optional<Output<String>> modelId() {
        return Optional.ofNullable(this.modelId);
    }

    private ModelComponentModelArgs() {}

    private ModelComponentModelArgs(ModelComponentModelArgs $) {
        this.modelId = $.modelId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelComponentModelArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelComponentModelArgs $;

        public Builder() {
            $ = new ModelComponentModelArgs();
        }

        public Builder(ModelComponentModelArgs defaults) {
            $ = new ModelComponentModelArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param modelId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of active custom Key Value model that need to be composed.
         * 
         * @return builder
         * 
         */
        public Builder modelId(@Nullable Output<String> modelId) {
            $.modelId = modelId;
            return this;
        }

        /**
         * @param modelId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of active custom Key Value model that need to be composed.
         * 
         * @return builder
         * 
         */
        public Builder modelId(String modelId) {
            return modelId(Output.of(modelId));
        }

        public ModelComponentModelArgs build() {
            return $;
        }
    }

}