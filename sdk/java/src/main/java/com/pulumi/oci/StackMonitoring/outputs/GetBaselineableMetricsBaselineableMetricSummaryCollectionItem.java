// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetBaselineableMetricsBaselineableMetricSummaryCollectionItem {
    /**
     * @return metric column name
     * 
     */
    private String column;
    /**
     * @return The ID of the compartment in which data is listed.
     * 
     */
    private String compartmentId;
    /**
     * @return Created user id
     * 
     */
    private String createdBy;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return OCID of the metric
     * 
     */
    private String id;
    /**
     * @return Is the metric created out of box, default false
     * 
     */
    private Boolean isOutOfBox;
    /**
     * @return last Updated user id
     * 
     */
    private String lastUpdatedBy;
    /**
     * @return Metric Name
     * 
     */
    private String name;
    /**
     * @return namespace of the metric
     * 
     */
    private String namespace;
    /**
     * @return Resource Group
     * 
     */
    private String resourceGroup;
    /**
     * @return The current lifecycle state of the metric extension
     * 
     */
    private String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return OCID of the tenancy
     * 
     */
    private String tenancyId;
    /**
     * @return creation date
     * 
     */
    private String timeCreated;
    /**
     * @return last updated time
     * 
     */
    private String timeLastUpdated;

    private GetBaselineableMetricsBaselineableMetricSummaryCollectionItem() {}
    /**
     * @return metric column name
     * 
     */
    public String column() {
        return this.column;
    }
    /**
     * @return The ID of the compartment in which data is listed.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Created user id
     * 
     */
    public String createdBy() {
        return this.createdBy;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return OCID of the metric
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Is the metric created out of box, default false
     * 
     */
    public Boolean isOutOfBox() {
        return this.isOutOfBox;
    }
    /**
     * @return last Updated user id
     * 
     */
    public String lastUpdatedBy() {
        return this.lastUpdatedBy;
    }
    /**
     * @return Metric Name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return namespace of the metric
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return Resource Group
     * 
     */
    public String resourceGroup() {
        return this.resourceGroup;
    }
    /**
     * @return The current lifecycle state of the metric extension
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return OCID of the tenancy
     * 
     */
    public String tenancyId() {
        return this.tenancyId;
    }
    /**
     * @return creation date
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return last updated time
     * 
     */
    public String timeLastUpdated() {
        return this.timeLastUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBaselineableMetricsBaselineableMetricSummaryCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String column;
        private String compartmentId;
        private String createdBy;
        private Map<String,Object> definedTags;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isOutOfBox;
        private String lastUpdatedBy;
        private String name;
        private String namespace;
        private String resourceGroup;
        private String state;
        private Map<String,Object> systemTags;
        private String tenancyId;
        private String timeCreated;
        private String timeLastUpdated;
        public Builder() {}
        public Builder(GetBaselineableMetricsBaselineableMetricSummaryCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.column = defaults.column;
    	      this.compartmentId = defaults.compartmentId;
    	      this.createdBy = defaults.createdBy;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isOutOfBox = defaults.isOutOfBox;
    	      this.lastUpdatedBy = defaults.lastUpdatedBy;
    	      this.name = defaults.name;
    	      this.namespace = defaults.namespace;
    	      this.resourceGroup = defaults.resourceGroup;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.tenancyId = defaults.tenancyId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLastUpdated = defaults.timeLastUpdated;
        }

        @CustomType.Setter
        public Builder column(String column) {
            this.column = Objects.requireNonNull(column);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder createdBy(String createdBy) {
            this.createdBy = Objects.requireNonNull(createdBy);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isOutOfBox(Boolean isOutOfBox) {
            this.isOutOfBox = Objects.requireNonNull(isOutOfBox);
            return this;
        }
        @CustomType.Setter
        public Builder lastUpdatedBy(String lastUpdatedBy) {
            this.lastUpdatedBy = Objects.requireNonNull(lastUpdatedBy);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder resourceGroup(String resourceGroup) {
            this.resourceGroup = Objects.requireNonNull(resourceGroup);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder tenancyId(String tenancyId) {
            this.tenancyId = Objects.requireNonNull(tenancyId);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeLastUpdated(String timeLastUpdated) {
            this.timeLastUpdated = Objects.requireNonNull(timeLastUpdated);
            return this;
        }
        public GetBaselineableMetricsBaselineableMetricSummaryCollectionItem build() {
            final var o = new GetBaselineableMetricsBaselineableMetricSummaryCollectionItem();
            o.column = column;
            o.compartmentId = compartmentId;
            o.createdBy = createdBy;
            o.definedTags = definedTags;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isOutOfBox = isOutOfBox;
            o.lastUpdatedBy = lastUpdatedBy;
            o.name = name;
            o.namespace = namespace;
            o.resourceGroup = resourceGroup;
            o.state = state;
            o.systemTags = systemTags;
            o.tenancyId = tenancyId;
            o.timeCreated = timeCreated;
            o.timeLastUpdated = timeLastUpdated;
            return o;
        }
    }
}