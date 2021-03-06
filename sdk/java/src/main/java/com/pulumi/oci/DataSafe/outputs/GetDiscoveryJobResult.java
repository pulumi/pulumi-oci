// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDiscoveryJobResult {
    /**
     * @return The OCID of the compartment that contains the discovery job.
     * 
     */
    private final String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    private final String discoveryJobId;
    /**
     * @return The type of the discovery job. It defines the job&#39;s scope. NEW identifies new sensitive columns in the target database that are not in the sensitive data model. DELETED identifies columns that are present in the sensitive data model but have been deleted from the target database. MODIFIED identifies columns that are present in the target database as well as the sensitive data model but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
     * 
     */
    private final String discoveryType;
    /**
     * @return The display name of the discovery job.
     * 
     */
    private final String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The OCID of the discovery job.
     * 
     */
    private final String id;
    /**
     * @return Indicates if the discovery job should identify potential application-level (non-dictionary) referential relationships between columns. Note that data discovery automatically identifies and adds database-level (dictionary-defined) relationships. This option helps identify application-level relationships that are not defined in the database dictionary, which in turn, helps identify additional sensitive columns and preserve referential integrity during data masking. It&#39;s disabled by default and should be used only if there is a need to identify application-level relationships.
     * 
     */
    private final Boolean isAppDefinedRelationDiscoveryEnabled;
    /**
     * @return Indicates if all the schemas in the associated target database are used for data discovery. If it&#39;s set to true, the schemasForDiscovery attribute is ignored and all schemas are used.
     * 
     */
    private final Boolean isIncludeAllSchemas;
    /**
     * @return Indicates if all the existing sensitive types are used for data discovery. If it&#39;s set to true, the sensitiveTypeIdsForDiscovery attribute is ignored and all sensitive types are used.
     * 
     */
    private final Boolean isIncludeAllSensitiveTypes;
    /**
     * @return Indicates if the discovery job should collect and store sample data values for the discovered columns. Sample data helps review the discovered columns and ensure that they actually contain sensitive data. As it collects original data from the target database, it&#39;s disabled by default and should be used only if it&#39;s acceptable to store sample data in Data Safe&#39;s repository in Oracle Cloud. Note that sample data values are not collected for columns with the following data types: LONG, LOB, RAW, XMLTYPE and BFILE.
     * 
     */
    private final Boolean isSampleDataCollectionEnabled;
    /**
     * @return The schemas used for data discovery.
     * 
     */
    private final List<String> schemasForDiscoveries;
    /**
     * @return The OCID of the sensitive data model associated with the discovery job.
     * 
     */
    private final String sensitiveDataModelId;
    /**
     * @return The OCIDs of the sensitive types used for data discovery.
     * 
     */
    private final List<String> sensitiveTypeIdsForDiscoveries;
    /**
     * @return The current state of the discovery job.
     * 
     */
    private final String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private final Map<String,Object> systemTags;
    /**
     * @return The OCID of the target database associated with the discovery job.
     * 
     */
    private final String targetId;
    /**
     * @return The date and time the discovery job finished, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)..
     * 
     */
    private final String timeFinished;
    /**
     * @return The date and time the discovery job started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private final String timeStarted;
    /**
     * @return The total number of columns scanned by the discovery job.
     * 
     */
    private final String totalColumnsScanned;
    /**
     * @return The total number of deleted sensitive columns identified by the discovery job.
     * 
     */
    private final String totalDeletedSensitiveColumns;
    /**
     * @return The total number of modified sensitive columns identified by the discovery job.
     * 
     */
    private final String totalModifiedSensitiveColumns;
    /**
     * @return The total number of new sensitive columns identified by the discovery job.
     * 
     */
    private final String totalNewSensitiveColumns;
    /**
     * @return The total number of objects (tables and editioning views) scanned by the discovery job.
     * 
     */
    private final String totalObjectsScanned;
    /**
     * @return The total number of schemas scanned by the discovery job.
     * 
     */
    private final String totalSchemasScanned;

    @CustomType.Constructor
    private GetDiscoveryJobResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("discoveryJobId") String discoveryJobId,
        @CustomType.Parameter("discoveryType") String discoveryType,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isAppDefinedRelationDiscoveryEnabled") Boolean isAppDefinedRelationDiscoveryEnabled,
        @CustomType.Parameter("isIncludeAllSchemas") Boolean isIncludeAllSchemas,
        @CustomType.Parameter("isIncludeAllSensitiveTypes") Boolean isIncludeAllSensitiveTypes,
        @CustomType.Parameter("isSampleDataCollectionEnabled") Boolean isSampleDataCollectionEnabled,
        @CustomType.Parameter("schemasForDiscoveries") List<String> schemasForDiscoveries,
        @CustomType.Parameter("sensitiveDataModelId") String sensitiveDataModelId,
        @CustomType.Parameter("sensitiveTypeIdsForDiscoveries") List<String> sensitiveTypeIdsForDiscoveries,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("systemTags") Map<String,Object> systemTags,
        @CustomType.Parameter("targetId") String targetId,
        @CustomType.Parameter("timeFinished") String timeFinished,
        @CustomType.Parameter("timeStarted") String timeStarted,
        @CustomType.Parameter("totalColumnsScanned") String totalColumnsScanned,
        @CustomType.Parameter("totalDeletedSensitiveColumns") String totalDeletedSensitiveColumns,
        @CustomType.Parameter("totalModifiedSensitiveColumns") String totalModifiedSensitiveColumns,
        @CustomType.Parameter("totalNewSensitiveColumns") String totalNewSensitiveColumns,
        @CustomType.Parameter("totalObjectsScanned") String totalObjectsScanned,
        @CustomType.Parameter("totalSchemasScanned") String totalSchemasScanned) {
        this.compartmentId = compartmentId;
        this.definedTags = definedTags;
        this.discoveryJobId = discoveryJobId;
        this.discoveryType = discoveryType;
        this.displayName = displayName;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isAppDefinedRelationDiscoveryEnabled = isAppDefinedRelationDiscoveryEnabled;
        this.isIncludeAllSchemas = isIncludeAllSchemas;
        this.isIncludeAllSensitiveTypes = isIncludeAllSensitiveTypes;
        this.isSampleDataCollectionEnabled = isSampleDataCollectionEnabled;
        this.schemasForDiscoveries = schemasForDiscoveries;
        this.sensitiveDataModelId = sensitiveDataModelId;
        this.sensitiveTypeIdsForDiscoveries = sensitiveTypeIdsForDiscoveries;
        this.state = state;
        this.systemTags = systemTags;
        this.targetId = targetId;
        this.timeFinished = timeFinished;
        this.timeStarted = timeStarted;
        this.totalColumnsScanned = totalColumnsScanned;
        this.totalDeletedSensitiveColumns = totalDeletedSensitiveColumns;
        this.totalModifiedSensitiveColumns = totalModifiedSensitiveColumns;
        this.totalNewSensitiveColumns = totalNewSensitiveColumns;
        this.totalObjectsScanned = totalObjectsScanned;
        this.totalSchemasScanned = totalSchemasScanned;
    }

    /**
     * @return The OCID of the compartment that contains the discovery job.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    public String discoveryJobId() {
        return this.discoveryJobId;
    }
    /**
     * @return The type of the discovery job. It defines the job&#39;s scope. NEW identifies new sensitive columns in the target database that are not in the sensitive data model. DELETED identifies columns that are present in the sensitive data model but have been deleted from the target database. MODIFIED identifies columns that are present in the target database as well as the sensitive data model but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
     * 
     */
    public String discoveryType() {
        return this.discoveryType;
    }
    /**
     * @return The display name of the discovery job.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the discovery job.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates if the discovery job should identify potential application-level (non-dictionary) referential relationships between columns. Note that data discovery automatically identifies and adds database-level (dictionary-defined) relationships. This option helps identify application-level relationships that are not defined in the database dictionary, which in turn, helps identify additional sensitive columns and preserve referential integrity during data masking. It&#39;s disabled by default and should be used only if there is a need to identify application-level relationships.
     * 
     */
    public Boolean isAppDefinedRelationDiscoveryEnabled() {
        return this.isAppDefinedRelationDiscoveryEnabled;
    }
    /**
     * @return Indicates if all the schemas in the associated target database are used for data discovery. If it&#39;s set to true, the schemasForDiscovery attribute is ignored and all schemas are used.
     * 
     */
    public Boolean isIncludeAllSchemas() {
        return this.isIncludeAllSchemas;
    }
    /**
     * @return Indicates if all the existing sensitive types are used for data discovery. If it&#39;s set to true, the sensitiveTypeIdsForDiscovery attribute is ignored and all sensitive types are used.
     * 
     */
    public Boolean isIncludeAllSensitiveTypes() {
        return this.isIncludeAllSensitiveTypes;
    }
    /**
     * @return Indicates if the discovery job should collect and store sample data values for the discovered columns. Sample data helps review the discovered columns and ensure that they actually contain sensitive data. As it collects original data from the target database, it&#39;s disabled by default and should be used only if it&#39;s acceptable to store sample data in Data Safe&#39;s repository in Oracle Cloud. Note that sample data values are not collected for columns with the following data types: LONG, LOB, RAW, XMLTYPE and BFILE.
     * 
     */
    public Boolean isSampleDataCollectionEnabled() {
        return this.isSampleDataCollectionEnabled;
    }
    /**
     * @return The schemas used for data discovery.
     * 
     */
    public List<String> schemasForDiscoveries() {
        return this.schemasForDiscoveries;
    }
    /**
     * @return The OCID of the sensitive data model associated with the discovery job.
     * 
     */
    public String sensitiveDataModelId() {
        return this.sensitiveDataModelId;
    }
    /**
     * @return The OCIDs of the sensitive types used for data discovery.
     * 
     */
    public List<String> sensitiveTypeIdsForDiscoveries() {
        return this.sensitiveTypeIdsForDiscoveries;
    }
    /**
     * @return The current state of the discovery job.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The OCID of the target database associated with the discovery job.
     * 
     */
    public String targetId() {
        return this.targetId;
    }
    /**
     * @return The date and time the discovery job finished, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)..
     * 
     */
    public String timeFinished() {
        return this.timeFinished;
    }
    /**
     * @return The date and time the discovery job started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }
    /**
     * @return The total number of columns scanned by the discovery job.
     * 
     */
    public String totalColumnsScanned() {
        return this.totalColumnsScanned;
    }
    /**
     * @return The total number of deleted sensitive columns identified by the discovery job.
     * 
     */
    public String totalDeletedSensitiveColumns() {
        return this.totalDeletedSensitiveColumns;
    }
    /**
     * @return The total number of modified sensitive columns identified by the discovery job.
     * 
     */
    public String totalModifiedSensitiveColumns() {
        return this.totalModifiedSensitiveColumns;
    }
    /**
     * @return The total number of new sensitive columns identified by the discovery job.
     * 
     */
    public String totalNewSensitiveColumns() {
        return this.totalNewSensitiveColumns;
    }
    /**
     * @return The total number of objects (tables and editioning views) scanned by the discovery job.
     * 
     */
    public String totalObjectsScanned() {
        return this.totalObjectsScanned;
    }
    /**
     * @return The total number of schemas scanned by the discovery job.
     * 
     */
    public String totalSchemasScanned() {
        return this.totalSchemasScanned;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDiscoveryJobResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private Map<String,Object> definedTags;
        private String discoveryJobId;
        private String discoveryType;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isAppDefinedRelationDiscoveryEnabled;
        private Boolean isIncludeAllSchemas;
        private Boolean isIncludeAllSensitiveTypes;
        private Boolean isSampleDataCollectionEnabled;
        private List<String> schemasForDiscoveries;
        private String sensitiveDataModelId;
        private List<String> sensitiveTypeIdsForDiscoveries;
        private String state;
        private Map<String,Object> systemTags;
        private String targetId;
        private String timeFinished;
        private String timeStarted;
        private String totalColumnsScanned;
        private String totalDeletedSensitiveColumns;
        private String totalModifiedSensitiveColumns;
        private String totalNewSensitiveColumns;
        private String totalObjectsScanned;
        private String totalSchemasScanned;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDiscoveryJobResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.discoveryJobId = defaults.discoveryJobId;
    	      this.discoveryType = defaults.discoveryType;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isAppDefinedRelationDiscoveryEnabled = defaults.isAppDefinedRelationDiscoveryEnabled;
    	      this.isIncludeAllSchemas = defaults.isIncludeAllSchemas;
    	      this.isIncludeAllSensitiveTypes = defaults.isIncludeAllSensitiveTypes;
    	      this.isSampleDataCollectionEnabled = defaults.isSampleDataCollectionEnabled;
    	      this.schemasForDiscoveries = defaults.schemasForDiscoveries;
    	      this.sensitiveDataModelId = defaults.sensitiveDataModelId;
    	      this.sensitiveTypeIdsForDiscoveries = defaults.sensitiveTypeIdsForDiscoveries;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.targetId = defaults.targetId;
    	      this.timeFinished = defaults.timeFinished;
    	      this.timeStarted = defaults.timeStarted;
    	      this.totalColumnsScanned = defaults.totalColumnsScanned;
    	      this.totalDeletedSensitiveColumns = defaults.totalDeletedSensitiveColumns;
    	      this.totalModifiedSensitiveColumns = defaults.totalModifiedSensitiveColumns;
    	      this.totalNewSensitiveColumns = defaults.totalNewSensitiveColumns;
    	      this.totalObjectsScanned = defaults.totalObjectsScanned;
    	      this.totalSchemasScanned = defaults.totalSchemasScanned;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder discoveryJobId(String discoveryJobId) {
            this.discoveryJobId = Objects.requireNonNull(discoveryJobId);
            return this;
        }
        public Builder discoveryType(String discoveryType) {
            this.discoveryType = Objects.requireNonNull(discoveryType);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
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
        public Builder isAppDefinedRelationDiscoveryEnabled(Boolean isAppDefinedRelationDiscoveryEnabled) {
            this.isAppDefinedRelationDiscoveryEnabled = Objects.requireNonNull(isAppDefinedRelationDiscoveryEnabled);
            return this;
        }
        public Builder isIncludeAllSchemas(Boolean isIncludeAllSchemas) {
            this.isIncludeAllSchemas = Objects.requireNonNull(isIncludeAllSchemas);
            return this;
        }
        public Builder isIncludeAllSensitiveTypes(Boolean isIncludeAllSensitiveTypes) {
            this.isIncludeAllSensitiveTypes = Objects.requireNonNull(isIncludeAllSensitiveTypes);
            return this;
        }
        public Builder isSampleDataCollectionEnabled(Boolean isSampleDataCollectionEnabled) {
            this.isSampleDataCollectionEnabled = Objects.requireNonNull(isSampleDataCollectionEnabled);
            return this;
        }
        public Builder schemasForDiscoveries(List<String> schemasForDiscoveries) {
            this.schemasForDiscoveries = Objects.requireNonNull(schemasForDiscoveries);
            return this;
        }
        public Builder schemasForDiscoveries(String... schemasForDiscoveries) {
            return schemasForDiscoveries(List.of(schemasForDiscoveries));
        }
        public Builder sensitiveDataModelId(String sensitiveDataModelId) {
            this.sensitiveDataModelId = Objects.requireNonNull(sensitiveDataModelId);
            return this;
        }
        public Builder sensitiveTypeIdsForDiscoveries(List<String> sensitiveTypeIdsForDiscoveries) {
            this.sensitiveTypeIdsForDiscoveries = Objects.requireNonNull(sensitiveTypeIdsForDiscoveries);
            return this;
        }
        public Builder sensitiveTypeIdsForDiscoveries(String... sensitiveTypeIdsForDiscoveries) {
            return sensitiveTypeIdsForDiscoveries(List.of(sensitiveTypeIdsForDiscoveries));
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        public Builder targetId(String targetId) {
            this.targetId = Objects.requireNonNull(targetId);
            return this;
        }
        public Builder timeFinished(String timeFinished) {
            this.timeFinished = Objects.requireNonNull(timeFinished);
            return this;
        }
        public Builder timeStarted(String timeStarted) {
            this.timeStarted = Objects.requireNonNull(timeStarted);
            return this;
        }
        public Builder totalColumnsScanned(String totalColumnsScanned) {
            this.totalColumnsScanned = Objects.requireNonNull(totalColumnsScanned);
            return this;
        }
        public Builder totalDeletedSensitiveColumns(String totalDeletedSensitiveColumns) {
            this.totalDeletedSensitiveColumns = Objects.requireNonNull(totalDeletedSensitiveColumns);
            return this;
        }
        public Builder totalModifiedSensitiveColumns(String totalModifiedSensitiveColumns) {
            this.totalModifiedSensitiveColumns = Objects.requireNonNull(totalModifiedSensitiveColumns);
            return this;
        }
        public Builder totalNewSensitiveColumns(String totalNewSensitiveColumns) {
            this.totalNewSensitiveColumns = Objects.requireNonNull(totalNewSensitiveColumns);
            return this;
        }
        public Builder totalObjectsScanned(String totalObjectsScanned) {
            this.totalObjectsScanned = Objects.requireNonNull(totalObjectsScanned);
            return this;
        }
        public Builder totalSchemasScanned(String totalSchemasScanned) {
            this.totalSchemasScanned = Objects.requireNonNull(totalSchemasScanned);
            return this;
        }        public GetDiscoveryJobResult build() {
            return new GetDiscoveryJobResult(compartmentId, definedTags, discoveryJobId, discoveryType, displayName, freeformTags, id, isAppDefinedRelationDiscoveryEnabled, isIncludeAllSchemas, isIncludeAllSensitiveTypes, isSampleDataCollectionEnabled, schemasForDiscoveries, sensitiveDataModelId, sensitiveTypeIdsForDiscoveries, state, systemTags, targetId, timeFinished, timeStarted, totalColumnsScanned, totalDeletedSensitiveColumns, totalModifiedSensitiveColumns, totalNewSensitiveColumns, totalObjectsScanned, totalSchemasScanned);
        }
    }
}
