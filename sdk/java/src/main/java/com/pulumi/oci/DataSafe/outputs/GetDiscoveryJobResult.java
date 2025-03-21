// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetDiscoveryJobTablesForDiscovery;
import java.lang.Boolean;
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
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    private String discoveryJobId;
    /**
     * @return The type of the discovery job. It defines the job&#39;s scope. NEW identifies new sensitive columns in the target database that are not in the sensitive data model. DELETED identifies columns that are present in the sensitive data model but have been deleted from the target database. MODIFIED identifies columns that are present in the target database as well as the sensitive data model but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
     * 
     */
    private String discoveryType;
    /**
     * @return The display name of the discovery job.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the discovery job.
     * 
     */
    private String id;
    /**
     * @return Indicates if the discovery job should identify potential application-level (non-dictionary) referential relationships between columns. Note that data discovery automatically identifies and adds database-level (dictionary-defined) relationships. This option helps identify application-level relationships that are not defined in the database dictionary, which in turn, helps identify additional sensitive columns and preserve referential integrity during data masking. It&#39;s disabled by default and should be used only if there is a need to identify application-level relationships.
     * 
     */
    private Boolean isAppDefinedRelationDiscoveryEnabled;
    /**
     * @return Indicates if all the schemas in the associated target database are used for data discovery. If it is set to true, sensitive data is discovered in all schemas (except for schemas maintained by Oracle).
     * 
     */
    private Boolean isIncludeAllSchemas;
    /**
     * @return Indicates if all the existing sensitive types are used for data discovery. If it&#39;s set to true, the sensitiveTypeIdsForDiscovery attribute is ignored and all sensitive types are used.
     * 
     */
    private Boolean isIncludeAllSensitiveTypes;
    /**
     * @return Indicates if the discovery job should collect and store sample data values for the discovered columns. Sample data helps review the discovered columns and ensure that they actually contain sensitive data. As it collects original data from the target database, it&#39;s disabled by default and should be used only if it&#39;s acceptable to store sample data in Data Safe&#39;s repository in Oracle Cloud. Note that sample data values are not collected for columns with the following data types: LONG, LOB, RAW, XMLTYPE and BFILE.
     * 
     */
    private Boolean isSampleDataCollectionEnabled;
    /**
     * @return The schemas used for data discovery.
     * 
     */
    private List<String> schemasForDiscoveries;
    /**
     * @return The OCID of the sensitive data model associated with the discovery job.
     * 
     */
    private String sensitiveDataModelId;
    /**
     * @return The OCIDs of the sensitive type groups to be used by data discovery jobs.
     * 
     */
    private List<String> sensitiveTypeGroupIdsForDiscoveries;
    /**
     * @return The OCIDs of the sensitive types used for data discovery.
     * 
     */
    private List<String> sensitiveTypeIdsForDiscoveries;
    /**
     * @return The current state of the discovery job.
     * 
     */
    private String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The data discovery jobs will scan the tables specified here, including both schemas and tables.
     * 
     */
    private List<GetDiscoveryJobTablesForDiscovery> tablesForDiscoveries;
    /**
     * @return The OCID of the target database associated with the discovery job.
     * 
     */
    private String targetId;
    /**
     * @return The date and time the discovery job finished, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)..
     * 
     */
    private String timeFinished;
    /**
     * @return The date and time the discovery job started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeStarted;
    /**
     * @return The total number of columns scanned by the discovery job.
     * 
     */
    private String totalColumnsScanned;
    /**
     * @return The total number of deleted sensitive columns identified by the discovery job.
     * 
     */
    private String totalDeletedSensitiveColumns;
    /**
     * @return The total number of modified sensitive columns identified by the discovery job.
     * 
     */
    private String totalModifiedSensitiveColumns;
    /**
     * @return The total number of new sensitive columns identified by the discovery job.
     * 
     */
    private String totalNewSensitiveColumns;
    /**
     * @return The total number of objects (tables and editioning views) scanned by the discovery job.
     * 
     */
    private String totalObjectsScanned;
    /**
     * @return The total number of schemas scanned by the discovery job.
     * 
     */
    private String totalSchemasScanned;

    private GetDiscoveryJobResult() {}
    /**
     * @return The OCID of the compartment that contains the discovery job.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
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
    public Map<String,String> freeformTags() {
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
     * @return Indicates if all the schemas in the associated target database are used for data discovery. If it is set to true, sensitive data is discovered in all schemas (except for schemas maintained by Oracle).
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
     * @return The OCIDs of the sensitive type groups to be used by data discovery jobs.
     * 
     */
    public List<String> sensitiveTypeGroupIdsForDiscoveries() {
        return this.sensitiveTypeGroupIdsForDiscoveries;
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
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The data discovery jobs will scan the tables specified here, including both schemas and tables.
     * 
     */
    public List<GetDiscoveryJobTablesForDiscovery> tablesForDiscoveries() {
        return this.tablesForDiscoveries;
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
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String discoveryJobId;
        private String discoveryType;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isAppDefinedRelationDiscoveryEnabled;
        private Boolean isIncludeAllSchemas;
        private Boolean isIncludeAllSensitiveTypes;
        private Boolean isSampleDataCollectionEnabled;
        private List<String> schemasForDiscoveries;
        private String sensitiveDataModelId;
        private List<String> sensitiveTypeGroupIdsForDiscoveries;
        private List<String> sensitiveTypeIdsForDiscoveries;
        private String state;
        private Map<String,String> systemTags;
        private List<GetDiscoveryJobTablesForDiscovery> tablesForDiscoveries;
        private String targetId;
        private String timeFinished;
        private String timeStarted;
        private String totalColumnsScanned;
        private String totalDeletedSensitiveColumns;
        private String totalModifiedSensitiveColumns;
        private String totalNewSensitiveColumns;
        private String totalObjectsScanned;
        private String totalSchemasScanned;
        public Builder() {}
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
    	      this.sensitiveTypeGroupIdsForDiscoveries = defaults.sensitiveTypeGroupIdsForDiscoveries;
    	      this.sensitiveTypeIdsForDiscoveries = defaults.sensitiveTypeIdsForDiscoveries;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.tablesForDiscoveries = defaults.tablesForDiscoveries;
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

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder discoveryJobId(String discoveryJobId) {
            if (discoveryJobId == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "discoveryJobId");
            }
            this.discoveryJobId = discoveryJobId;
            return this;
        }
        @CustomType.Setter
        public Builder discoveryType(String discoveryType) {
            if (discoveryType == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "discoveryType");
            }
            this.discoveryType = discoveryType;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isAppDefinedRelationDiscoveryEnabled(Boolean isAppDefinedRelationDiscoveryEnabled) {
            if (isAppDefinedRelationDiscoveryEnabled == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "isAppDefinedRelationDiscoveryEnabled");
            }
            this.isAppDefinedRelationDiscoveryEnabled = isAppDefinedRelationDiscoveryEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isIncludeAllSchemas(Boolean isIncludeAllSchemas) {
            if (isIncludeAllSchemas == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "isIncludeAllSchemas");
            }
            this.isIncludeAllSchemas = isIncludeAllSchemas;
            return this;
        }
        @CustomType.Setter
        public Builder isIncludeAllSensitiveTypes(Boolean isIncludeAllSensitiveTypes) {
            if (isIncludeAllSensitiveTypes == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "isIncludeAllSensitiveTypes");
            }
            this.isIncludeAllSensitiveTypes = isIncludeAllSensitiveTypes;
            return this;
        }
        @CustomType.Setter
        public Builder isSampleDataCollectionEnabled(Boolean isSampleDataCollectionEnabled) {
            if (isSampleDataCollectionEnabled == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "isSampleDataCollectionEnabled");
            }
            this.isSampleDataCollectionEnabled = isSampleDataCollectionEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder schemasForDiscoveries(List<String> schemasForDiscoveries) {
            if (schemasForDiscoveries == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "schemasForDiscoveries");
            }
            this.schemasForDiscoveries = schemasForDiscoveries;
            return this;
        }
        public Builder schemasForDiscoveries(String... schemasForDiscoveries) {
            return schemasForDiscoveries(List.of(schemasForDiscoveries));
        }
        @CustomType.Setter
        public Builder sensitiveDataModelId(String sensitiveDataModelId) {
            if (sensitiveDataModelId == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "sensitiveDataModelId");
            }
            this.sensitiveDataModelId = sensitiveDataModelId;
            return this;
        }
        @CustomType.Setter
        public Builder sensitiveTypeGroupIdsForDiscoveries(List<String> sensitiveTypeGroupIdsForDiscoveries) {
            if (sensitiveTypeGroupIdsForDiscoveries == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "sensitiveTypeGroupIdsForDiscoveries");
            }
            this.sensitiveTypeGroupIdsForDiscoveries = sensitiveTypeGroupIdsForDiscoveries;
            return this;
        }
        public Builder sensitiveTypeGroupIdsForDiscoveries(String... sensitiveTypeGroupIdsForDiscoveries) {
            return sensitiveTypeGroupIdsForDiscoveries(List.of(sensitiveTypeGroupIdsForDiscoveries));
        }
        @CustomType.Setter
        public Builder sensitiveTypeIdsForDiscoveries(List<String> sensitiveTypeIdsForDiscoveries) {
            if (sensitiveTypeIdsForDiscoveries == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "sensitiveTypeIdsForDiscoveries");
            }
            this.sensitiveTypeIdsForDiscoveries = sensitiveTypeIdsForDiscoveries;
            return this;
        }
        public Builder sensitiveTypeIdsForDiscoveries(String... sensitiveTypeIdsForDiscoveries) {
            return sensitiveTypeIdsForDiscoveries(List.of(sensitiveTypeIdsForDiscoveries));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder tablesForDiscoveries(List<GetDiscoveryJobTablesForDiscovery> tablesForDiscoveries) {
            if (tablesForDiscoveries == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "tablesForDiscoveries");
            }
            this.tablesForDiscoveries = tablesForDiscoveries;
            return this;
        }
        public Builder tablesForDiscoveries(GetDiscoveryJobTablesForDiscovery... tablesForDiscoveries) {
            return tablesForDiscoveries(List.of(tablesForDiscoveries));
        }
        @CustomType.Setter
        public Builder targetId(String targetId) {
            if (targetId == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "targetId");
            }
            this.targetId = targetId;
            return this;
        }
        @CustomType.Setter
        public Builder timeFinished(String timeFinished) {
            if (timeFinished == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "timeFinished");
            }
            this.timeFinished = timeFinished;
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(String timeStarted) {
            if (timeStarted == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "timeStarted");
            }
            this.timeStarted = timeStarted;
            return this;
        }
        @CustomType.Setter
        public Builder totalColumnsScanned(String totalColumnsScanned) {
            if (totalColumnsScanned == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "totalColumnsScanned");
            }
            this.totalColumnsScanned = totalColumnsScanned;
            return this;
        }
        @CustomType.Setter
        public Builder totalDeletedSensitiveColumns(String totalDeletedSensitiveColumns) {
            if (totalDeletedSensitiveColumns == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "totalDeletedSensitiveColumns");
            }
            this.totalDeletedSensitiveColumns = totalDeletedSensitiveColumns;
            return this;
        }
        @CustomType.Setter
        public Builder totalModifiedSensitiveColumns(String totalModifiedSensitiveColumns) {
            if (totalModifiedSensitiveColumns == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "totalModifiedSensitiveColumns");
            }
            this.totalModifiedSensitiveColumns = totalModifiedSensitiveColumns;
            return this;
        }
        @CustomType.Setter
        public Builder totalNewSensitiveColumns(String totalNewSensitiveColumns) {
            if (totalNewSensitiveColumns == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "totalNewSensitiveColumns");
            }
            this.totalNewSensitiveColumns = totalNewSensitiveColumns;
            return this;
        }
        @CustomType.Setter
        public Builder totalObjectsScanned(String totalObjectsScanned) {
            if (totalObjectsScanned == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "totalObjectsScanned");
            }
            this.totalObjectsScanned = totalObjectsScanned;
            return this;
        }
        @CustomType.Setter
        public Builder totalSchemasScanned(String totalSchemasScanned) {
            if (totalSchemasScanned == null) {
              throw new MissingRequiredPropertyException("GetDiscoveryJobResult", "totalSchemasScanned");
            }
            this.totalSchemasScanned = totalSchemasScanned;
            return this;
        }
        public GetDiscoveryJobResult build() {
            final var _resultValue = new GetDiscoveryJobResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.discoveryJobId = discoveryJobId;
            _resultValue.discoveryType = discoveryType;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isAppDefinedRelationDiscoveryEnabled = isAppDefinedRelationDiscoveryEnabled;
            _resultValue.isIncludeAllSchemas = isIncludeAllSchemas;
            _resultValue.isIncludeAllSensitiveTypes = isIncludeAllSensitiveTypes;
            _resultValue.isSampleDataCollectionEnabled = isSampleDataCollectionEnabled;
            _resultValue.schemasForDiscoveries = schemasForDiscoveries;
            _resultValue.sensitiveDataModelId = sensitiveDataModelId;
            _resultValue.sensitiveTypeGroupIdsForDiscoveries = sensitiveTypeGroupIdsForDiscoveries;
            _resultValue.sensitiveTypeIdsForDiscoveries = sensitiveTypeIdsForDiscoveries;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.tablesForDiscoveries = tablesForDiscoveries;
            _resultValue.targetId = targetId;
            _resultValue.timeFinished = timeFinished;
            _resultValue.timeStarted = timeStarted;
            _resultValue.totalColumnsScanned = totalColumnsScanned;
            _resultValue.totalDeletedSensitiveColumns = totalDeletedSensitiveColumns;
            _resultValue.totalModifiedSensitiveColumns = totalModifiedSensitiveColumns;
            _resultValue.totalNewSensitiveColumns = totalNewSensitiveColumns;
            _resultValue.totalObjectsScanned = totalObjectsScanned;
            _resultValue.totalSchemasScanned = totalSchemasScanned;
            return _resultValue;
        }
    }
}
