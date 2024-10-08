// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Nosql.outputs.GetTablesTableCollectionReplica;
import com.pulumi.oci.Nosql.outputs.GetTablesTableCollectionSchema;
import com.pulumi.oci.Nosql.outputs.GetTablesTableCollectionTableLimit;
import java.lang.Boolean;
import java.lang.Integer;
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
    private String ddlStatement;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
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
     * @return True if this table is currently a member of a replication set.
     * 
     */
    private Boolean isMultiRegion;
    /**
     * @return A message describing the current state in more detail.
     * 
     */
    private String lifecycleDetails;
    private Integer localReplicaInitializationInPercent;
    /**
     * @return A shell-globbing-style (*?[]) filter for names.
     * 
     */
    private String name;
    private List<GetTablesTableCollectionReplica> replicas;
    /**
     * @return The current state of this table&#39;s schema. Available states are MUTABLE - The schema can be changed. The table is not eligible for replication. FROZEN - The schema is immutable. The table is eligible for replication.
     * 
     */
    private String schemaState;
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
    private Map<String,String> systemTags;
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
    public String ddlStatement() {
        return this.ddlStatement;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
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
     * @return True if this table is currently a member of a replication set.
     * 
     */
    public Boolean isMultiRegion() {
        return this.isMultiRegion;
    }
    /**
     * @return A message describing the current state in more detail.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    public Integer localReplicaInitializationInPercent() {
        return this.localReplicaInitializationInPercent;
    }
    /**
     * @return A shell-globbing-style (*?[]) filter for names.
     * 
     */
    public String name() {
        return this.name;
    }
    public List<GetTablesTableCollectionReplica> replicas() {
        return this.replicas;
    }
    /**
     * @return The current state of this table&#39;s schema. Available states are MUTABLE - The schema can be changed. The table is not eligible for replication. FROZEN - The schema is immutable. The table is eligible for replication.
     * 
     */
    public String schemaState() {
        return this.schemaState;
    }
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
    public Map<String,String> systemTags() {
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
        private Map<String,String> definedTags;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isAutoReclaimable;
        private Boolean isMultiRegion;
        private String lifecycleDetails;
        private Integer localReplicaInitializationInPercent;
        private String name;
        private List<GetTablesTableCollectionReplica> replicas;
        private String schemaState;
        private List<GetTablesTableCollectionSchema> schemas;
        private String state;
        private Map<String,String> systemTags;
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
    	      this.isMultiRegion = defaults.isMultiRegion;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.localReplicaInitializationInPercent = defaults.localReplicaInitializationInPercent;
    	      this.name = defaults.name;
    	      this.replicas = defaults.replicas;
    	      this.schemaState = defaults.schemaState;
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
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder ddlStatement(String ddlStatement) {
            if (ddlStatement == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "ddlStatement");
            }
            this.ddlStatement = ddlStatement;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isAutoReclaimable(Boolean isAutoReclaimable) {
            if (isAutoReclaimable == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "isAutoReclaimable");
            }
            this.isAutoReclaimable = isAutoReclaimable;
            return this;
        }
        @CustomType.Setter
        public Builder isMultiRegion(Boolean isMultiRegion) {
            if (isMultiRegion == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "isMultiRegion");
            }
            this.isMultiRegion = isMultiRegion;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder localReplicaInitializationInPercent(Integer localReplicaInitializationInPercent) {
            if (localReplicaInitializationInPercent == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "localReplicaInitializationInPercent");
            }
            this.localReplicaInitializationInPercent = localReplicaInitializationInPercent;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder replicas(List<GetTablesTableCollectionReplica> replicas) {
            if (replicas == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "replicas");
            }
            this.replicas = replicas;
            return this;
        }
        public Builder replicas(GetTablesTableCollectionReplica... replicas) {
            return replicas(List.of(replicas));
        }
        @CustomType.Setter
        public Builder schemaState(String schemaState) {
            if (schemaState == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "schemaState");
            }
            this.schemaState = schemaState;
            return this;
        }
        @CustomType.Setter
        public Builder schemas(List<GetTablesTableCollectionSchema> schemas) {
            if (schemas == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "schemas");
            }
            this.schemas = schemas;
            return this;
        }
        public Builder schemas(GetTablesTableCollectionSchema... schemas) {
            return schemas(List.of(schemas));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder tableLimits(List<GetTablesTableCollectionTableLimit> tableLimits) {
            if (tableLimits == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "tableLimits");
            }
            this.tableLimits = tableLimits;
            return this;
        }
        public Builder tableLimits(GetTablesTableCollectionTableLimit... tableLimits) {
            return tableLimits(List.of(tableLimits));
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeOfExpiration(String timeOfExpiration) {
            if (timeOfExpiration == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "timeOfExpiration");
            }
            this.timeOfExpiration = timeOfExpiration;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetTablesTableCollection", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetTablesTableCollection build() {
            final var _resultValue = new GetTablesTableCollection();
            _resultValue.compartmentId = compartmentId;
            _resultValue.ddlStatement = ddlStatement;
            _resultValue.definedTags = definedTags;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isAutoReclaimable = isAutoReclaimable;
            _resultValue.isMultiRegion = isMultiRegion;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.localReplicaInitializationInPercent = localReplicaInitializationInPercent;
            _resultValue.name = name;
            _resultValue.replicas = replicas;
            _resultValue.schemaState = schemaState;
            _resultValue.schemas = schemas;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.tableLimits = tableLimits;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeOfExpiration = timeOfExpiration;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
