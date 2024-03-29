// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.AiLanguage.inputs.ModelEvaluationResultClassMetricArgs;
import com.pulumi.oci.AiLanguage.inputs.ModelEvaluationResultEntityMetricArgs;
import com.pulumi.oci.AiLanguage.inputs.ModelEvaluationResultMetricArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelEvaluationResultArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelEvaluationResultArgs Empty = new ModelEvaluationResultArgs();

    /**
     * List of text classification metrics
     * 
     */
    @Import(name="classMetrics")
    private @Nullable Output<List<ModelEvaluationResultClassMetricArgs>> classMetrics;

    /**
     * @return List of text classification metrics
     * 
     */
    public Optional<Output<List<ModelEvaluationResultClassMetricArgs>>> classMetrics() {
        return Optional.ofNullable(this.classMetrics);
    }

    /**
     * class level confusion matrix
     * 
     */
    @Import(name="confusionMatrix")
    private @Nullable Output<String> confusionMatrix;

    /**
     * @return class level confusion matrix
     * 
     */
    public Optional<Output<String>> confusionMatrix() {
        return Optional.ofNullable(this.confusionMatrix);
    }

    /**
     * List of entity metrics
     * 
     */
    @Import(name="entityMetrics")
    private @Nullable Output<List<ModelEvaluationResultEntityMetricArgs>> entityMetrics;

    /**
     * @return List of entity metrics
     * 
     */
    public Optional<Output<List<ModelEvaluationResultEntityMetricArgs>>> entityMetrics() {
        return Optional.ofNullable(this.entityMetrics);
    }

    /**
     * labels
     * 
     */
    @Import(name="labels")
    private @Nullable Output<List<String>> labels;

    /**
     * @return labels
     * 
     */
    public Optional<Output<List<String>>> labels() {
        return Optional.ofNullable(this.labels);
    }

    /**
     * Model level named entity recognition metrics
     * 
     */
    @Import(name="metrics")
    private @Nullable Output<List<ModelEvaluationResultMetricArgs>> metrics;

    /**
     * @return Model level named entity recognition metrics
     * 
     */
    public Optional<Output<List<ModelEvaluationResultMetricArgs>>> metrics() {
        return Optional.ofNullable(this.metrics);
    }

    /**
     * Model type
     * 
     */
    @Import(name="modelType")
    private @Nullable Output<String> modelType;

    /**
     * @return Model type
     * 
     */
    public Optional<Output<String>> modelType() {
        return Optional.ofNullable(this.modelType);
    }

    private ModelEvaluationResultArgs() {}

    private ModelEvaluationResultArgs(ModelEvaluationResultArgs $) {
        this.classMetrics = $.classMetrics;
        this.confusionMatrix = $.confusionMatrix;
        this.entityMetrics = $.entityMetrics;
        this.labels = $.labels;
        this.metrics = $.metrics;
        this.modelType = $.modelType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelEvaluationResultArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelEvaluationResultArgs $;

        public Builder() {
            $ = new ModelEvaluationResultArgs();
        }

        public Builder(ModelEvaluationResultArgs defaults) {
            $ = new ModelEvaluationResultArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param classMetrics List of text classification metrics
         * 
         * @return builder
         * 
         */
        public Builder classMetrics(@Nullable Output<List<ModelEvaluationResultClassMetricArgs>> classMetrics) {
            $.classMetrics = classMetrics;
            return this;
        }

        /**
         * @param classMetrics List of text classification metrics
         * 
         * @return builder
         * 
         */
        public Builder classMetrics(List<ModelEvaluationResultClassMetricArgs> classMetrics) {
            return classMetrics(Output.of(classMetrics));
        }

        /**
         * @param classMetrics List of text classification metrics
         * 
         * @return builder
         * 
         */
        public Builder classMetrics(ModelEvaluationResultClassMetricArgs... classMetrics) {
            return classMetrics(List.of(classMetrics));
        }

        /**
         * @param confusionMatrix class level confusion matrix
         * 
         * @return builder
         * 
         */
        public Builder confusionMatrix(@Nullable Output<String> confusionMatrix) {
            $.confusionMatrix = confusionMatrix;
            return this;
        }

        /**
         * @param confusionMatrix class level confusion matrix
         * 
         * @return builder
         * 
         */
        public Builder confusionMatrix(String confusionMatrix) {
            return confusionMatrix(Output.of(confusionMatrix));
        }

        /**
         * @param entityMetrics List of entity metrics
         * 
         * @return builder
         * 
         */
        public Builder entityMetrics(@Nullable Output<List<ModelEvaluationResultEntityMetricArgs>> entityMetrics) {
            $.entityMetrics = entityMetrics;
            return this;
        }

        /**
         * @param entityMetrics List of entity metrics
         * 
         * @return builder
         * 
         */
        public Builder entityMetrics(List<ModelEvaluationResultEntityMetricArgs> entityMetrics) {
            return entityMetrics(Output.of(entityMetrics));
        }

        /**
         * @param entityMetrics List of entity metrics
         * 
         * @return builder
         * 
         */
        public Builder entityMetrics(ModelEvaluationResultEntityMetricArgs... entityMetrics) {
            return entityMetrics(List.of(entityMetrics));
        }

        /**
         * @param labels labels
         * 
         * @return builder
         * 
         */
        public Builder labels(@Nullable Output<List<String>> labels) {
            $.labels = labels;
            return this;
        }

        /**
         * @param labels labels
         * 
         * @return builder
         * 
         */
        public Builder labels(List<String> labels) {
            return labels(Output.of(labels));
        }

        /**
         * @param labels labels
         * 
         * @return builder
         * 
         */
        public Builder labels(String... labels) {
            return labels(List.of(labels));
        }

        /**
         * @param metrics Model level named entity recognition metrics
         * 
         * @return builder
         * 
         */
        public Builder metrics(@Nullable Output<List<ModelEvaluationResultMetricArgs>> metrics) {
            $.metrics = metrics;
            return this;
        }

        /**
         * @param metrics Model level named entity recognition metrics
         * 
         * @return builder
         * 
         */
        public Builder metrics(List<ModelEvaluationResultMetricArgs> metrics) {
            return metrics(Output.of(metrics));
        }

        /**
         * @param metrics Model level named entity recognition metrics
         * 
         * @return builder
         * 
         */
        public Builder metrics(ModelEvaluationResultMetricArgs... metrics) {
            return metrics(List.of(metrics));
        }

        /**
         * @param modelType Model type
         * 
         * @return builder
         * 
         */
        public Builder modelType(@Nullable Output<String> modelType) {
            $.modelType = modelType;
            return this;
        }

        /**
         * @param modelType Model type
         * 
         * @return builder
         * 
         */
        public Builder modelType(String modelType) {
            return modelType(Output.of(modelType));
        }

        public ModelEvaluationResultArgs build() {
            return $;
        }
    }

}
