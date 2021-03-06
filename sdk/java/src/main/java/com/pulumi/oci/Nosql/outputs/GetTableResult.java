// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Nosql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Nosql.outputs.GetTableSchema;
import com.pulumi.oci.Nosql.outputs.GetTableTableLimit;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetTableResult {
    /**
     * @return Compartment Identifier.
     * 
     */
    private final String compartmentId;
    /**
     * @return A DDL statement representing the schema.
     * 
     */
    private final String ddlStatement;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{&#34;foo-namespace&#34;: {&#34;bar-key&#34;: &#34;value&#34;}}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return Unique identifier that is immutable.
     * 
     */
    private final String id;
    /**
     * @return True if this table can be reclaimed after an idle period.
     * 
     */
    private final Boolean isAutoReclaimable;
    /**
     * @return A message describing the current state in more detail.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return The column name.
     * 
     */
    private final String name;
    /**
     * @return The table schema information as a JSON object.
     * 
     */
    private final List<GetTableSchema> schemas;
    /**
     * @return The state of a table.
     * 
     */
    private final String state;
    /**
     * @return Read-only system tag. These predefined keys are scoped to namespaces.  At present the only supported namespace is `&#34;orcl-cloud&#34;`; and the only key in that namespace is `&#34;free-tier-retained&#34;`. Example: `{&#34;orcl-cloud&#34;&#34;: {&#34;free-tier-retained&#34;: &#34;true&#34;}}`
     * 
     */
    private final Map<String,Object> systemTags;
    /**
     * @return Throughput and storage limits configuration of a table.
     * 
     */
    private final List<GetTableTableLimit> tableLimits;
    private final String tableNameOrId;
    /**
     * @return The time the the table was created. An RFC3339 formatted datetime string.
     * 
     */
    private final String timeCreated;
    /**
     * @return If lifecycleState is INACTIVE, indicates when this table will be automatically removed. An RFC3339 formatted datetime string.
     * 
     */
    private final String timeOfExpiration;
    /**
     * @return The time the the table&#39;s metadata was last updated. An RFC3339 formatted datetime string.
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetTableResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("ddlStatement") String ddlStatement,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isAutoReclaimable") Boolean isAutoReclaimable,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("schemas") List<GetTableSchema> schemas,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("systemTags") Map<String,Object> systemTags,
        @CustomType.Parameter("tableLimits") List<GetTableTableLimit> tableLimits,
        @CustomType.Parameter("tableNameOrId") String tableNameOrId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeOfExpiration") String timeOfExpiration,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.compartmentId = compartmentId;
        this.ddlStatement = ddlStatement;
        this.definedTags = definedTags;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isAutoReclaimable = isAutoReclaimable;
        this.lifecycleDetails = lifecycleDetails;
        this.name = name;
        this.schemas = schemas;
        this.state = state;
        this.systemTags = systemTags;
        this.tableLimits = tableLimits;
        this.tableNameOrId = tableNameOrId;
        this.timeCreated = timeCreated;
        this.timeOfExpiration = timeOfExpiration;
        this.timeUpdated = timeUpdated;
    }

    /**
     * @return Compartment Identifier.
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
     * @return The column name.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The table schema information as a JSON object.
     * 
     */
    public List<GetTableSchema> schemas() {
        return this.schemas;
    }
    /**
     * @return The state of a table.
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
    public List<GetTableTableLimit> tableLimits() {
        return this.tableLimits;
    }
    public String tableNameOrId() {
        return this.tableNameOrId;
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

    public static Builder builder(GetTableResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String ddlStatement;
        private Map<String,Object> definedTags;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isAutoReclaimable;
        private String lifecycleDetails;
        private String name;
        private List<GetTableSchema> schemas;
        private String state;
        private Map<String,Object> systemTags;
        private List<GetTableTableLimit> tableLimits;
        private String tableNameOrId;
        private String timeCreated;
        private String timeOfExpiration;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetTableResult defaults) {
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
    	      this.tableNameOrId = defaults.tableNameOrId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeOfExpiration = defaults.timeOfExpiration;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder ddlStatement(String ddlStatement) {
            this.ddlStatement = Objects.requireNonNull(ddlStatement);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder isAutoReclaimable(Boolean isAutoReclaimable) {
            this.isAutoReclaimable = Objects.requireNonNull(isAutoReclaimable);
            return this;
        }
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder schemas(List<GetTableSchema> schemas) {
            this.schemas = Objects.requireNonNull(schemas);
            return this;
        }
        public Builder schemas(GetTableSchema... schemas) {
            return schemas(List.of(schemas));
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        public Builder tableLimits(List<GetTableTableLimit> tableLimits) {
            this.tableLimits = Objects.requireNonNull(tableLimits);
            return this;
        }
        public Builder tableLimits(GetTableTableLimit... tableLimits) {
            return tableLimits(List.of(tableLimits));
        }
        public Builder tableNameOrId(String tableNameOrId) {
            this.tableNameOrId = Objects.requireNonNull(tableNameOrId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeOfExpiration(String timeOfExpiration) {
            this.timeOfExpiration = Objects.requireNonNull(timeOfExpiration);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetTableResult build() {
            return new GetTableResult(compartmentId, ddlStatement, definedTags, freeformTags, id, isAutoReclaimable, lifecycleDetails, name, schemas, state, systemTags, tableLimits, tableNameOrId, timeCreated, timeOfExpiration, timeUpdated);
        }
    }
}
