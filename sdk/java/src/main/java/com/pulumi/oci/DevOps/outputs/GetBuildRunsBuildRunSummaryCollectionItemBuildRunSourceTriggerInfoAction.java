// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.outputs.GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoActionFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoAction {
    /**
     * @return Unique build pipeline identifier.
     * 
     */
    private String buildPipelineId;
    private List<GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoActionFilter> filters;
    /**
     * @return The type of action that will be taken. Allowed value is TRIGGER_BUILD_PIPELINE.
     * 
     */
    private String type;

    private GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoAction() {}
    /**
     * @return Unique build pipeline identifier.
     * 
     */
    public String buildPipelineId() {
        return this.buildPipelineId;
    }
    public List<GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoActionFilter> filters() {
        return this.filters;
    }
    /**
     * @return The type of action that will be taken. Allowed value is TRIGGER_BUILD_PIPELINE.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoAction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String buildPipelineId;
        private List<GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoActionFilter> filters;
        private String type;
        public Builder() {}
        public Builder(GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoAction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.buildPipelineId = defaults.buildPipelineId;
    	      this.filters = defaults.filters;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder buildPipelineId(String buildPipelineId) {
            if (buildPipelineId == null) {
              throw new MissingRequiredPropertyException("GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoAction", "buildPipelineId");
            }
            this.buildPipelineId = buildPipelineId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(List<GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoActionFilter> filters) {
            if (filters == null) {
              throw new MissingRequiredPropertyException("GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoAction", "filters");
            }
            this.filters = filters;
            return this;
        }
        public Builder filters(GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoActionFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoAction", "type");
            }
            this.type = type;
            return this;
        }
        public GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoAction build() {
            final var _resultValue = new GetBuildRunsBuildRunSummaryCollectionItemBuildRunSourceTriggerInfoAction();
            _resultValue.buildPipelineId = buildPipelineId;
            _resultValue.filters = filters;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
