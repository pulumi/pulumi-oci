// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.inputs.ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationArgs;
import com.pulumi.oci.DataScience.inputs.ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs Empty = new ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs();

    /**
     * (Updatable) The minimum network bandwidth for the model deployment.
     * 
     */
    @Import(name="bandwidthMbps")
    private @Nullable Output<Integer> bandwidthMbps;

    /**
     * @return (Updatable) The minimum network bandwidth for the model deployment.
     * 
     */
    public Optional<Output<Integer>> bandwidthMbps() {
        return Optional.ofNullable(this.bandwidthMbps);
    }

    /**
     * (Updatable) The model deployment instance configuration
     * 
     */
    @Import(name="instanceConfiguration", required=true)
    private Output<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationArgs> instanceConfiguration;

    /**
     * @return (Updatable) The model deployment instance configuration
     * 
     */
    public Output<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationArgs> instanceConfiguration() {
        return this.instanceConfiguration;
    }

    /**
     * (Updatable) The maximum network bandwidth for the model deployment.
     * 
     */
    @Import(name="maximumBandwidthMbps")
    private @Nullable Output<Integer> maximumBandwidthMbps;

    /**
     * @return (Updatable) The maximum network bandwidth for the model deployment.
     * 
     */
    public Optional<Output<Integer>> maximumBandwidthMbps() {
        return Optional.ofNullable(this.maximumBandwidthMbps);
    }

    /**
     * (Updatable) The OCID of the model you want to deploy.
     * 
     */
    @Import(name="modelId", required=true)
    private Output<String> modelId;

    /**
     * @return (Updatable) The OCID of the model you want to deploy.
     * 
     */
    public Output<String> modelId() {
        return this.modelId;
    }

    /**
     * (Updatable) The scaling policy to apply to each model of the deployment.
     * 
     */
    @Import(name="scalingPolicy")
    private @Nullable Output<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs> scalingPolicy;

    /**
     * @return (Updatable) The scaling policy to apply to each model of the deployment.
     * 
     */
    public Optional<Output<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs>> scalingPolicy() {
        return Optional.ofNullable(this.scalingPolicy);
    }

    private ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs() {}

    private ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs $) {
        this.bandwidthMbps = $.bandwidthMbps;
        this.instanceConfiguration = $.instanceConfiguration;
        this.maximumBandwidthMbps = $.maximumBandwidthMbps;
        this.modelId = $.modelId;
        this.scalingPolicy = $.scalingPolicy;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs $;

        public Builder() {
            $ = new ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs();
        }

        public Builder(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs defaults) {
            $ = new ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bandwidthMbps (Updatable) The minimum network bandwidth for the model deployment.
         * 
         * @return builder
         * 
         */
        public Builder bandwidthMbps(@Nullable Output<Integer> bandwidthMbps) {
            $.bandwidthMbps = bandwidthMbps;
            return this;
        }

        /**
         * @param bandwidthMbps (Updatable) The minimum network bandwidth for the model deployment.
         * 
         * @return builder
         * 
         */
        public Builder bandwidthMbps(Integer bandwidthMbps) {
            return bandwidthMbps(Output.of(bandwidthMbps));
        }

        /**
         * @param instanceConfiguration (Updatable) The model deployment instance configuration
         * 
         * @return builder
         * 
         */
        public Builder instanceConfiguration(Output<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationArgs> instanceConfiguration) {
            $.instanceConfiguration = instanceConfiguration;
            return this;
        }

        /**
         * @param instanceConfiguration (Updatable) The model deployment instance configuration
         * 
         * @return builder
         * 
         */
        public Builder instanceConfiguration(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationArgs instanceConfiguration) {
            return instanceConfiguration(Output.of(instanceConfiguration));
        }

        /**
         * @param maximumBandwidthMbps (Updatable) The maximum network bandwidth for the model deployment.
         * 
         * @return builder
         * 
         */
        public Builder maximumBandwidthMbps(@Nullable Output<Integer> maximumBandwidthMbps) {
            $.maximumBandwidthMbps = maximumBandwidthMbps;
            return this;
        }

        /**
         * @param maximumBandwidthMbps (Updatable) The maximum network bandwidth for the model deployment.
         * 
         * @return builder
         * 
         */
        public Builder maximumBandwidthMbps(Integer maximumBandwidthMbps) {
            return maximumBandwidthMbps(Output.of(maximumBandwidthMbps));
        }

        /**
         * @param modelId (Updatable) The OCID of the model you want to deploy.
         * 
         * @return builder
         * 
         */
        public Builder modelId(Output<String> modelId) {
            $.modelId = modelId;
            return this;
        }

        /**
         * @param modelId (Updatable) The OCID of the model you want to deploy.
         * 
         * @return builder
         * 
         */
        public Builder modelId(String modelId) {
            return modelId(Output.of(modelId));
        }

        /**
         * @param scalingPolicy (Updatable) The scaling policy to apply to each model of the deployment.
         * 
         * @return builder
         * 
         */
        public Builder scalingPolicy(@Nullable Output<ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs> scalingPolicy) {
            $.scalingPolicy = scalingPolicy;
            return this;
        }

        /**
         * @param scalingPolicy (Updatable) The scaling policy to apply to each model of the deployment.
         * 
         * @return builder
         * 
         */
        public Builder scalingPolicy(ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs scalingPolicy) {
            return scalingPolicy(Output.of(scalingPolicy));
        }

        public ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs build() {
            if ($.instanceConfiguration == null) {
                throw new MissingRequiredPropertyException("ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs", "instanceConfiguration");
            }
            if ($.modelId == null) {
                throw new MissingRequiredPropertyException("ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs", "modelId");
            }
            return $;
        }
    }

}
