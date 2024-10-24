// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItem {
    /**
     * @return Default value of the parameter.
     * 
     */
    private String defaultValue;
    /**
     * @return Optional description about the build pipeline.
     * 
     */
    private String description;
    /**
     * @return Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
     * 
     */
    private String name;

    private GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItem() {}
    /**
     * @return Default value of the parameter.
     * 
     */
    public String defaultValue() {
        return this.defaultValue;
    }
    /**
     * @return Optional description about the build pipeline.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: &#39;Build_Pipeline_param&#39; is not same as &#39;build_pipeline_Param&#39;
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String defaultValue;
        private String description;
        private String name;
        public Builder() {}
        public Builder(GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.defaultValue = defaults.defaultValue;
    	      this.description = defaults.description;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder defaultValue(String defaultValue) {
            if (defaultValue == null) {
              throw new MissingRequiredPropertyException("GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItem", "defaultValue");
            }
            this.defaultValue = defaultValue;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItem", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItem", "name");
            }
            this.name = name;
            return this;
        }
        public GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItem build() {
            final var _resultValue = new GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItem();
            _resultValue.defaultValue = defaultValue;
            _resultValue.description = description;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
