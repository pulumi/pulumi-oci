// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.GetModelDeploymentCategoryLogDetail;
import com.pulumi.oci.DataScience.outputs.GetModelDeploymentModelDeploymentConfigurationDetail;
import com.pulumi.oci.DataScience.outputs.GetModelDeploymentModelDeploymentSystemData;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetModelDeploymentResult {
    /**
     * @return The log details for each category.
     * 
     */
    private List<GetModelDeploymentCategoryLogDetail> categoryLogDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment&#39;s compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model deployment.
     * 
     */
    private String createdBy;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A short description of the model deployment.
     * 
     */
    private String description;
    /**
     * @return A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
     * 
     */
    private String id;
    /**
     * @return Details about the state of the model deployment.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The model deployment configuration details.
     * 
     */
    private List<GetModelDeploymentModelDeploymentConfigurationDetail> modelDeploymentConfigurationDetails;
    private String modelDeploymentId;
    /**
     * @return Model deployment system data.
     * 
     */
    private List<GetModelDeploymentModelDeploymentSystemData> modelDeploymentSystemDatas;
    /**
     * @return The URL to interact with the model deployment.
     * 
     */
    private String modelDeploymentUrl;
    private String opcParentRptUrl;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model deployment.
     * 
     */
    private String projectId;
    /**
     * @return The state of the model deployment.
     * 
     */
    private String state;
    /**
     * @return The date and time the resource was created, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
     * 
     */
    private String timeCreated;

    private GetModelDeploymentResult() {}
    /**
     * @return The log details for each category.
     * 
     */
    public List<GetModelDeploymentCategoryLogDetail> categoryLogDetails() {
        return this.categoryLogDetails;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment&#39;s compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the model deployment.
     * 
     */
    public String createdBy() {
        return this.createdBy;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A short description of the model deployment.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A user-friendly display name for the resource. Does not have to be unique, and can be modified. Avoid entering confidential information. Example: `My ModelDeployment`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model deployment.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Details about the state of the model deployment.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The model deployment configuration details.
     * 
     */
    public List<GetModelDeploymentModelDeploymentConfigurationDetail> modelDeploymentConfigurationDetails() {
        return this.modelDeploymentConfigurationDetails;
    }
    public String modelDeploymentId() {
        return this.modelDeploymentId;
    }
    /**
     * @return Model deployment system data.
     * 
     */
    public List<GetModelDeploymentModelDeploymentSystemData> modelDeploymentSystemDatas() {
        return this.modelDeploymentSystemDatas;
    }
    /**
     * @return The URL to interact with the model deployment.
     * 
     */
    public String modelDeploymentUrl() {
        return this.modelDeploymentUrl;
    }
    public String opcParentRptUrl() {
        return this.opcParentRptUrl;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project associated with the model deployment.
     * 
     */
    public String projectId() {
        return this.projectId;
    }
    /**
     * @return The state of the model deployment.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the resource was created, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelDeploymentResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetModelDeploymentCategoryLogDetail> categoryLogDetails;
        private String compartmentId;
        private String createdBy;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String lifecycleDetails;
        private List<GetModelDeploymentModelDeploymentConfigurationDetail> modelDeploymentConfigurationDetails;
        private String modelDeploymentId;
        private List<GetModelDeploymentModelDeploymentSystemData> modelDeploymentSystemDatas;
        private String modelDeploymentUrl;
        private String opcParentRptUrl;
        private String projectId;
        private String state;
        private String timeCreated;
        public Builder() {}
        public Builder(GetModelDeploymentResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.categoryLogDetails = defaults.categoryLogDetails;
    	      this.compartmentId = defaults.compartmentId;
    	      this.createdBy = defaults.createdBy;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.modelDeploymentConfigurationDetails = defaults.modelDeploymentConfigurationDetails;
    	      this.modelDeploymentId = defaults.modelDeploymentId;
    	      this.modelDeploymentSystemDatas = defaults.modelDeploymentSystemDatas;
    	      this.modelDeploymentUrl = defaults.modelDeploymentUrl;
    	      this.opcParentRptUrl = defaults.opcParentRptUrl;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder categoryLogDetails(List<GetModelDeploymentCategoryLogDetail> categoryLogDetails) {
            if (categoryLogDetails == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "categoryLogDetails");
            }
            this.categoryLogDetails = categoryLogDetails;
            return this;
        }
        public Builder categoryLogDetails(GetModelDeploymentCategoryLogDetail... categoryLogDetails) {
            return categoryLogDetails(List.of(categoryLogDetails));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder createdBy(String createdBy) {
            if (createdBy == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "createdBy");
            }
            this.createdBy = createdBy;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder modelDeploymentConfigurationDetails(List<GetModelDeploymentModelDeploymentConfigurationDetail> modelDeploymentConfigurationDetails) {
            if (modelDeploymentConfigurationDetails == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "modelDeploymentConfigurationDetails");
            }
            this.modelDeploymentConfigurationDetails = modelDeploymentConfigurationDetails;
            return this;
        }
        public Builder modelDeploymentConfigurationDetails(GetModelDeploymentModelDeploymentConfigurationDetail... modelDeploymentConfigurationDetails) {
            return modelDeploymentConfigurationDetails(List.of(modelDeploymentConfigurationDetails));
        }
        @CustomType.Setter
        public Builder modelDeploymentId(String modelDeploymentId) {
            if (modelDeploymentId == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "modelDeploymentId");
            }
            this.modelDeploymentId = modelDeploymentId;
            return this;
        }
        @CustomType.Setter
        public Builder modelDeploymentSystemDatas(List<GetModelDeploymentModelDeploymentSystemData> modelDeploymentSystemDatas) {
            if (modelDeploymentSystemDatas == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "modelDeploymentSystemDatas");
            }
            this.modelDeploymentSystemDatas = modelDeploymentSystemDatas;
            return this;
        }
        public Builder modelDeploymentSystemDatas(GetModelDeploymentModelDeploymentSystemData... modelDeploymentSystemDatas) {
            return modelDeploymentSystemDatas(List.of(modelDeploymentSystemDatas));
        }
        @CustomType.Setter
        public Builder modelDeploymentUrl(String modelDeploymentUrl) {
            if (modelDeploymentUrl == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "modelDeploymentUrl");
            }
            this.modelDeploymentUrl = modelDeploymentUrl;
            return this;
        }
        @CustomType.Setter
        public Builder opcParentRptUrl(String opcParentRptUrl) {
            if (opcParentRptUrl == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "opcParentRptUrl");
            }
            this.opcParentRptUrl = opcParentRptUrl;
            return this;
        }
        @CustomType.Setter
        public Builder projectId(String projectId) {
            if (projectId == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "projectId");
            }
            this.projectId = projectId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetModelDeploymentResult build() {
            final var _resultValue = new GetModelDeploymentResult();
            _resultValue.categoryLogDetails = categoryLogDetails;
            _resultValue.compartmentId = compartmentId;
            _resultValue.createdBy = createdBy;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.modelDeploymentConfigurationDetails = modelDeploymentConfigurationDetails;
            _resultValue.modelDeploymentId = modelDeploymentId;
            _resultValue.modelDeploymentSystemDatas = modelDeploymentSystemDatas;
            _resultValue.modelDeploymentUrl = modelDeploymentUrl;
            _resultValue.opcParentRptUrl = opcParentRptUrl;
            _resultValue.projectId = projectId;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
