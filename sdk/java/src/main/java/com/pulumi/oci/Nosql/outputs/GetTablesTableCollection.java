// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Nosql.outputs.GetTablesTableCollectionSchema;
import com.pulumi.oci.Nosql.outputs.GetTablesTableCollectionTableLimit;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetTablesTableCollection {
    /**
     * @return The ID of a table&#39;s compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return A DDL statement representing the schema.
     * 
     */
    private String ddlStatement;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return Unique identifier that is immutable.
     * 
     */
    private String id;
    /**
     * @return True if this table can be reclaimed after an idle period.
     * 
     */
    private Boolean isAutoReclaimable;
    /**
     * @return A message describing the current state in more detail.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return A shell-globbing-style (*?[]) filter for names.
     * 
     */
    private String name;
    /**
     * @return The table schema information as a JSON object.
     * 
     */
    private List<GetTablesTableCollectionSchema> schemas;
    /**
     * @return Filter list by the lifecycle state of the item.
     * 
     */
    private String state;
    /**
     * @return Read-only system tag. These predefined keys are scoped to namespaces.  At present the only supported namespace is `&#34;orcl-cloud&#34;`; and the only key in that namespace is `&#34;free-tier-retained&#34;`. Example: `{&#34;orcl-cloud&#34;&#34;: {&#34;free-tier-retained&#34;: &#34;true&#34;}}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return Throughput and storage limits configuration of a table.
     * 
     */
    private List<GetTablesTableCollectionTableLimit> tableLimits;
    /**
     * @return The time the the table was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return If lifecycleState is INACTIVE, indicates when this table will be automatically removed. An RFC3339 formatted datetime string.
     * 
     */
    private String timeOfExpiration;
    /**
     * @return The time the the table&#39;s metadata was last updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;

    private GetTablesTableCollection() {}
    /**
     * @return The ID of a table&#39;s compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A DDL statement representing the schema.
     * 
     */
    public String ddlStatement() {
        return this.ddlStatement;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
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
     * @return Unique identifier that is immutable.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return True if this table can be reclaimed after an idle period.
     * 
     */
    public Boolean isAutoReclaimable() {
        return this.isAutoReclaimable;
    }
    /**
     * @return A message describing the current state in more detail.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return A shell-globbing-style (*?[]) filter for names.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The table schema information as a JSON object.
     * 
     */
    public List<GetTablesTableCollectionSchema> schemas() {
        return this.schemas;
    }
    /**
     * @return Filter list by the lifecycle state of the item.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Read-only system tag. These predefined keys are scoped to namespaces.  At present the only supported namespace is `&#34;orcl-cloud&#34;`; and the only key in that namespace is `&#34;free-tier-retained&#34;`. Example: `{&#34;orcl-cloud&#34;&#34;: {&#34;free-tier-retained&#34;: &#34;true&#34;}}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return Throughput and storage limits configuration of a table.
     * 
     */
    public List<GetTablesTableCollectionTableLimit> tableLimits() {
        return this.tableLimits;
    }
    /**
     * @return The time the the table was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return If lifecycleState is INACTIVE, indicates when this table will be automatically removed. An RFC3339 formatted datetime string.
     * 
     */
    public String timeOfExpiration() {
        return this.timeOfExpiration;
    }
    /**
     * @return The time the the table&#39;s metadata was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTablesTableCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String ddlStatement;
        private Map<String,Object> definedTags;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isAutoReclaimable;
        private String lifecycleDetails;
        private String name;
        private List<GetTablesTableCollectionSchema> schemas;
        private String state;
        private Map<String,Object> systemTags;
        private List<GetTablesTableCollectionTableLimit> tableLimits;
        private String timeCreated;
        private String timeOfExpiration;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetTablesTableCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.ddlStatement = defaults.ddlStatement;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isAutoReclaimable = defaults.isAutoReclaimable;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.name = defaults.name;
    	      this.schemas = defaults.schemas;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.tableLimits = defaults.tableLimits;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeOfExpiration = defaults.timeOfExpiration;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder ddlStatement(String ddlStatement) {
            this.ddlStatement = Objects.requireNonNull(ddlStatement);
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
        public Builder isAutoReclaimable(Boolean isAutoReclaimable) {
            this.isAutoReclaimable = Objects.requireNonNull(isAutoReclaimable);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<GetTablesTableCollectionSchema> schemas) {
            this.schemas = Objects.requireNonNull(schemas);
            return this;
        }
        public Builder schemas(GetTablesTableCollectionSchema... schemas) {
            return schemas(List.of(schemas));
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
        public Builder tableLimits(List<GetTablesTableCollectionTableLimit> tableLimits) {
            this.tableLimits = Objects.requireNonNull(tableLimits);
            return this;
        }
        public Builder tableLimits(GetTablesTableCollectionTableLimit... tableLimits) {
            return tableLimits(List.of(tableLimits));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeOfExpiration(String timeOfExpiration) {
            this.timeOfExpiration = Objects.requireNonNull(timeOfExpiration);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetTablesTableCollection build() {
            final var o = new GetTablesTableCollection();
            o.compartmentId = compartmentId;
            o.ddlStatement = ddlStatement;
            o.definedTags = definedTags;
            o.freeformTags = freeformTags;
            o.id = id;
            o.isAutoReclaimable = isAutoReclaimable;
            o.lifecycleDetails = lifecycleDetails;
            o.name = name;
            o.schemas = schemas;
            o.state = state;
            o.systemTags = systemTags;
            o.tableLimits = tableLimits;
            o.timeCreated = timeCreated;
            o.timeOfExpiration = timeOfExpiration;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}