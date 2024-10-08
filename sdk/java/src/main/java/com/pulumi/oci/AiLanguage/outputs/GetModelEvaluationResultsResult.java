// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiLanguage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiLanguage.outputs.GetModelEvaluationResultsEvaluationResultCollection;
import com.pulumi.oci.AiLanguage.outputs.GetModelEvaluationResultsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetModelEvaluationResultsResult {
    /**
     * @return The list of evaluation_result_collection.
     * 
     */
    private List<GetModelEvaluationResultsEvaluationResultCollection> evaluationResultCollections;
    private @Nullable List<GetModelEvaluationResultsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String modelId;

    private GetModelEvaluationResultsResult() {}
    /**
     * @return The list of evaluation_result_collection.
     * 
     */
    public List<GetModelEvaluationResultsEvaluationResultCollection> evaluationResultCollections() {
        return this.evaluationResultCollections;
    }
    public List<GetModelEvaluationResultsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String modelId() {
        return this.modelId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelEvaluationResultsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetModelEvaluationResultsEvaluationResultCollection> evaluationResultCollections;
        private @Nullable List<GetModelEvaluationResultsFilter> filters;
        private String id;
        private String modelId;
        public Builder() {}
        public Builder(GetModelEvaluationResultsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.evaluationResultCollections = defaults.evaluationResultCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.modelId = defaults.modelId;
        }

        @CustomType.Setter
        public Builder evaluationResultCollections(List<GetModelEvaluationResultsEvaluationResultCollection> evaluationResultCollections) {
            if (evaluationResultCollections == null) {
              throw new MissingRequiredPropertyException("GetModelEvaluationResultsResult", "evaluationResultCollections");
            }
            this.evaluationResultCollections = evaluationResultCollections;
            return this;
        }
        public Builder evaluationResultCollections(GetModelEvaluationResultsEvaluationResultCollection... evaluationResultCollections) {
            return evaluationResultCollections(List.of(evaluationResultCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetModelEvaluationResultsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetModelEvaluationResultsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetModelEvaluationResultsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder modelId(String modelId) {
            if (modelId == null) {
              throw new MissingRequiredPropertyException("GetModelEvaluationResultsResult", "modelId");
            }
            this.modelId = modelId;
            return this;
        }
        public GetModelEvaluationResultsResult build() {
            final var _resultValue = new GetModelEvaluationResultsResult();
            _resultValue.evaluationResultCollections = evaluationResultCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.modelId = modelId;
            return _resultValue;
        }
    }
}
