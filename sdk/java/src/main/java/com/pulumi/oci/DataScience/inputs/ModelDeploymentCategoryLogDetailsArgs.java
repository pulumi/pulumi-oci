// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.ModelDeploymentCategoryLogDetailsAccessArgs;
import com.pulumi.oci.DataScience.inputs.ModelDeploymentCategoryLogDetailsPredictArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelDeploymentCategoryLogDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelDeploymentCategoryLogDetailsArgs Empty = new ModelDeploymentCategoryLogDetailsArgs();

    /**
     * (Updatable) The log details.
     * 
     */
    @Import(name="access")
    private @Nullable Output<ModelDeploymentCategoryLogDetailsAccessArgs> access;

    /**
     * @return (Updatable) The log details.
     * 
     */
    public Optional<Output<ModelDeploymentCategoryLogDetailsAccessArgs>> access() {
        return Optional.ofNullable(this.access);
    }

    /**
     * (Updatable) The log details.
     * 
     */
    @Import(name="predict")
    private @Nullable Output<ModelDeploymentCategoryLogDetailsPredictArgs> predict;

    /**
     * @return (Updatable) The log details.
     * 
     */
    public Optional<Output<ModelDeploymentCategoryLogDetailsPredictArgs>> predict() {
        return Optional.ofNullable(this.predict);
    }

    private ModelDeploymentCategoryLogDetailsArgs() {}

    private ModelDeploymentCategoryLogDetailsArgs(ModelDeploymentCategoryLogDetailsArgs $) {
        this.access = $.access;
        this.predict = $.predict;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelDeploymentCategoryLogDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelDeploymentCategoryLogDetailsArgs $;

        public Builder() {
            $ = new ModelDeploymentCategoryLogDetailsArgs();
        }

        public Builder(ModelDeploymentCategoryLogDetailsArgs defaults) {
            $ = new ModelDeploymentCategoryLogDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param access (Updatable) The log details.
         * 
         * @return builder
         * 
         */
        public Builder access(@Nullable Output<ModelDeploymentCategoryLogDetailsAccessArgs> access) {
            $.access = access;
            return this;
        }

        /**
         * @param access (Updatable) The log details.
         * 
         * @return builder
         * 
         */
        public Builder access(ModelDeploymentCategoryLogDetailsAccessArgs access) {
            return access(Output.of(access));
        }

        /**
         * @param predict (Updatable) The log details.
         * 
         * @return builder
         * 
         */
        public Builder predict(@Nullable Output<ModelDeploymentCategoryLogDetailsPredictArgs> predict) {
            $.predict = predict;
            return this;
        }

        /**
         * @param predict (Updatable) The log details.
         * 
         * @return builder
         * 
         */
        public Builder predict(ModelDeploymentCategoryLogDetailsPredictArgs predict) {
            return predict(Output.of(predict));
        }

        public ModelDeploymentCategoryLogDetailsArgs build() {
            return $;
        }
    }

}
