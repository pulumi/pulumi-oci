// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Optimizer.outputs.GetResourceActionAction;
import java.lang.Double;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetResourceActionResult {
    /**
     * @return Details about the recommended action.
     * 
     */
    private final List<GetResourceActionAction> actions;
    /**
     * @return The unique OCID associated with the category.
     * 
     */
    private final String categoryId;
    /**
     * @return The OCID of the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return The name associated with the compartment.
     * 
     */
    private final String compartmentName;
    /**
     * @return The estimated cost savings, in dollars, for the resource action.
     * 
     */
    private final Double estimatedCostSaving;
    /**
     * @return Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    private final Map<String,Object> extendedMetadata;
    /**
     * @return The unique OCID associated with the resource action.
     * 
     */
    private final String id;
    /**
     * @return Custom metadata key/value pairs for the resource action.
     * 
     */
    private final Map<String,Object> metadata;
    /**
     * @return The name assigned to the resource.
     * 
     */
    private final String name;
    /**
     * @return The unique OCID associated with the recommendation.
     * 
     */
    private final String recommendationId;
    private final String resourceActionId;
    /**
     * @return The unique OCID associated with the resource.
     * 
     */
    private final String resourceId;
    /**
     * @return The kind of resource.
     * 
     */
    private final String resourceType;
    /**
     * @return The resource action&#39;s current state.
     * 
     */
    private final String state;
    /**
     * @return The current status of the resource action.
     * 
     */
    private final String status;
    /**
     * @return The date and time the resource action details were created, in the format defined by RFC3339.
     * 
     */
    private final String timeCreated;
    /**
     * @return The date and time that the resource action entered its current status. The format is defined by RFC3339.
     * 
     */
    private final String timeStatusBegin;
    /**
     * @return The date and time the current status will change. The format is defined by RFC3339.
     * 
     */
    private final String timeStatusEnd;
    /**
     * @return The date and time the resource action details were last updated, in the format defined by RFC3339.
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetResourceActionResult(
        @CustomType.Parameter("actions") List<GetResourceActionAction> actions,
        @CustomType.Parameter("categoryId") String categoryId,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("compartmentName") String compartmentName,
        @CustomType.Parameter("estimatedCostSaving") Double estimatedCostSaving,
        @CustomType.Parameter("extendedMetadata") Map<String,Object> extendedMetadata,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("metadata") Map<String,Object> metadata,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("recommendationId") String recommendationId,
        @CustomType.Parameter("resourceActionId") String resourceActionId,
        @CustomType.Parameter("resourceId") String resourceId,
        @CustomType.Parameter("resourceType") String resourceType,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("status") String status,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeStatusBegin") String timeStatusBegin,
        @CustomType.Parameter("timeStatusEnd") String timeStatusEnd,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.actions = actions;
        this.categoryId = categoryId;
        this.compartmentId = compartmentId;
        this.compartmentName = compartmentName;
        this.estimatedCostSaving = estimatedCostSaving;
        this.extendedMetadata = extendedMetadata;
        this.id = id;
        this.metadata = metadata;
        this.name = name;
        this.recommendationId = recommendationId;
        this.resourceActionId = resourceActionId;
        this.resourceId = resourceId;
        this.resourceType = resourceType;
        this.state = state;
        this.status = status;
        this.timeCreated = timeCreated;
        this.timeStatusBegin = timeStatusBegin;
        this.timeStatusEnd = timeStatusEnd;
        this.timeUpdated = timeUpdated;
    }

    /**
     * @return Details about the recommended action.
     * 
     */
    public List<GetResourceActionAction> actions() {
        return this.actions;
    }
    /**
     * @return The unique OCID associated with the category.
     * 
     */
    public String categoryId() {
        return this.categoryId;
    }
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The name associated with the compartment.
     * 
     */
    public String compartmentName() {
        return this.compartmentName;
    }
    /**
     * @return The estimated cost savings, in dollars, for the resource action.
     * 
     */
    public Double estimatedCostSaving() {
        return this.estimatedCostSaving;
    }
    /**
     * @return Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
     * 
     */
    public Map<String,Object> extendedMetadata() {
        return this.extendedMetadata;
    }
    /**
     * @return The unique OCID associated with the resource action.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Custom metadata key/value pairs for the resource action.
     * 
     */
    public Map<String,Object> metadata() {
        return this.metadata;
    }
    /**
     * @return The name assigned to the resource.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The unique OCID associated with the recommendation.
     * 
     */
    public String recommendationId() {
        return this.recommendationId;
    }
    public String resourceActionId() {
        return this.resourceActionId;
    }
    /**
     * @return The unique OCID associated with the resource.
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }
    /**
     * @return The kind of resource.
     * 
     */
    public String resourceType() {
        return this.resourceType;
    }
    /**
     * @return The resource action&#39;s current state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The current status of the resource action.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The date and time the resource action details were created, in the format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time that the resource action entered its current status. The format is defined by RFC3339.
     * 
     */
    public String timeStatusBegin() {
        return this.timeStatusBegin;
    }
    /**
     * @return The date and time the current status will change. The format is defined by RFC3339.
     * 
     */
    public String timeStatusEnd() {
        return this.timeStatusEnd;
    }
    /**
     * @return The date and time the resource action details were last updated, in the format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetResourceActionResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetResourceActionAction> actions;
        private String categoryId;
        private String compartmentId;
        private String compartmentName;
        private Double estimatedCostSaving;
        private Map<String,Object> extendedMetadata;
        private String id;
        private Map<String,Object> metadata;
        private String name;
        private String recommendationId;
        private String resourceActionId;
        private String resourceId;
        private String resourceType;
        private String state;
        private String status;
        private String timeCreated;
        private String timeStatusBegin;
        private String timeStatusEnd;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetResourceActionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actions = defaults.actions;
    	      this.categoryId = defaults.categoryId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentName = defaults.compartmentName;
    	      this.estimatedCostSaving = defaults.estimatedCostSaving;
    	      this.extendedMetadata = defaults.extendedMetadata;
    	      this.id = defaults.id;
    	      this.metadata = defaults.metadata;
    	      this.name = defaults.name;
    	      this.recommendationId = defaults.recommendationId;
    	      this.resourceActionId = defaults.resourceActionId;
    	      this.resourceId = defaults.resourceId;
    	      this.resourceType = defaults.resourceType;
    	      this.state = defaults.state;
    	      this.status = defaults.status;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeStatusBegin = defaults.timeStatusBegin;
    	      this.timeStatusEnd = defaults.timeStatusEnd;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder actions(List<GetResourceActionAction> actions) {
            this.actions = Objects.requireNonNull(actions);
            return this;
        }
        public Builder actions(GetResourceActionAction... actions) {
            return actions(List.of(actions));
        }
        public Builder categoryId(String categoryId) {
            this.categoryId = Objects.requireNonNull(categoryId);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder compartmentName(String compartmentName) {
            this.compartmentName = Objects.requireNonNull(compartmentName);
            return this;
        }
        public Builder estimatedCostSaving(Double estimatedCostSaving) {
            this.estimatedCostSaving = Objects.requireNonNull(estimatedCostSaving);
            return this;
        }
        public Builder extendedMetadata(Map<String,Object> extendedMetadata) {
            this.extendedMetadata = Objects.requireNonNull(extendedMetadata);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder metadata(Map<String,Object> metadata) {
            this.metadata = Objects.requireNonNull(metadata);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder recommendationId(String recommendationId) {
            this.recommendationId = Objects.requireNonNull(recommendationId);
            return this;
        }
        public Builder resourceActionId(String resourceActionId) {
            this.resourceActionId = Objects.requireNonNull(resourceActionId);
            return this;
        }
        public Builder resourceId(String resourceId) {
            this.resourceId = Objects.requireNonNull(resourceId);
            return this;
        }
        public Builder resourceType(String resourceType) {
            this.resourceType = Objects.requireNonNull(resourceType);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeStatusBegin(String timeStatusBegin) {
            this.timeStatusBegin = Objects.requireNonNull(timeStatusBegin);
            return this;
        }
        public Builder timeStatusEnd(String timeStatusEnd) {
            this.timeStatusEnd = Objects.requireNonNull(timeStatusEnd);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetResourceActionResult build() {
            return new GetResourceActionResult(actions, categoryId, compartmentId, compartmentName, estimatedCostSaving, extendedMetadata, id, metadata, name, recommendationId, resourceActionId, resourceId, resourceType, state, status, timeCreated, timeStatusBegin, timeStatusEnd, timeUpdated);
        }
    }
}
