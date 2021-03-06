// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelModelTrainingDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelModelTrainingDetailsArgs Empty = new ModelModelTrainingDetailsArgs();

    /**
     * The list of OCIDs of the data assets to train the model. The dataAssets have to be in the same project where the ai model would reside.
     * 
     */
    @Import(name="dataAssetIds", required=true)
    private Output<List<String>> dataAssetIds;

    /**
     * @return The list of OCIDs of the data assets to train the model. The dataAssets have to be in the same project where the ai model would reside.
     * 
     */
    public Output<List<String>> dataAssetIds() {
        return this.dataAssetIds;
    }

    /**
     * A target model accuracy metric user provides as their requirement
     * 
     */
    @Import(name="targetFap")
    private @Nullable Output<Double> targetFap;

    /**
     * @return A target model accuracy metric user provides as their requirement
     * 
     */
    public Optional<Output<Double>> targetFap() {
        return Optional.ofNullable(this.targetFap);
    }

    /**
     * Fraction of total data that is used for training the model. The remaining is used for validation of the model.
     * 
     */
    @Import(name="trainingFraction")
    private @Nullable Output<Double> trainingFraction;

    /**
     * @return Fraction of total data that is used for training the model. The remaining is used for validation of the model.
     * 
     */
    public Optional<Output<Double>> trainingFraction() {
        return Optional.ofNullable(this.trainingFraction);
    }

    private ModelModelTrainingDetailsArgs() {}

    private ModelModelTrainingDetailsArgs(ModelModelTrainingDetailsArgs $) {
        this.dataAssetIds = $.dataAssetIds;
        this.targetFap = $.targetFap;
        this.trainingFraction = $.trainingFraction;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelModelTrainingDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelModelTrainingDetailsArgs $;

        public Builder() {
            $ = new ModelModelTrainingDetailsArgs();
        }

        public Builder(ModelModelTrainingDetailsArgs defaults) {
            $ = new ModelModelTrainingDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dataAssetIds The list of OCIDs of the data assets to train the model. The dataAssets have to be in the same project where the ai model would reside.
         * 
         * @return builder
         * 
         */
        public Builder dataAssetIds(Output<List<String>> dataAssetIds) {
            $.dataAssetIds = dataAssetIds;
            return this;
        }

        /**
         * @param dataAssetIds The list of OCIDs of the data assets to train the model. The dataAssets have to be in the same project where the ai model would reside.
         * 
         * @return builder
         * 
         */
        public Builder dataAssetIds(List<String> dataAssetIds) {
            return dataAssetIds(Output.of(dataAssetIds));
        }

        /**
         * @param dataAssetIds The list of OCIDs of the data assets to train the model. The dataAssets have to be in the same project where the ai model would reside.
         * 
         * @return builder
         * 
         */
        public Builder dataAssetIds(String... dataAssetIds) {
            return dataAssetIds(List.of(dataAssetIds));
        }

        /**
         * @param targetFap A target model accuracy metric user provides as their requirement
         * 
         * @return builder
         * 
         */
        public Builder targetFap(@Nullable Output<Double> targetFap) {
            $.targetFap = targetFap;
            return this;
        }

        /**
         * @param targetFap A target model accuracy metric user provides as their requirement
         * 
         * @return builder
         * 
         */
        public Builder targetFap(Double targetFap) {
            return targetFap(Output.of(targetFap));
        }

        /**
         * @param trainingFraction Fraction of total data that is used for training the model. The remaining is used for validation of the model.
         * 
         * @return builder
         * 
         */
        public Builder trainingFraction(@Nullable Output<Double> trainingFraction) {
            $.trainingFraction = trainingFraction;
            return this;
        }

        /**
         * @param trainingFraction Fraction of total data that is used for training the model. The remaining is used for validation of the model.
         * 
         * @return builder
         * 
         */
        public Builder trainingFraction(Double trainingFraction) {
            return trainingFraction(Output.of(trainingFraction));
        }

        public ModelModelTrainingDetailsArgs build() {
            $.dataAssetIds = Objects.requireNonNull($.dataAssetIds, "expected parameter 'dataAssetIds' to be non-null");
            return $;
        }
    }

}
