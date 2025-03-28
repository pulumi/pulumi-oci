// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataFlow.outputs.GetSqlEndpointDriverShapeConfig;
import com.pulumi.oci.DataFlow.outputs.GetSqlEndpointExecutorShapeConfig;
import com.pulumi.oci.DataFlow.outputs.GetSqlEndpointNetworkConfiguration;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSqlEndpointResult {
    /**
     * @return The OCID of a compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The description of the SQL Endpoint.
     * 
     */
    private String description;
    /**
     * @return The SQL Endpoint name, which can be changed.
     * 
     */
    private String displayName;
    /**
     * @return The shape of the SQL Endpoint driver instance.
     * 
     */
    private String driverShape;
    /**
     * @return This is used to configure the shape of the driver or executor if a flexible shape is used.
     * 
     */
    private List<GetSqlEndpointDriverShapeConfig> driverShapeConfigs;
    /**
     * @return The shape of the SQL Endpoint executor instance.
     * 
     */
    private String executorShape;
    /**
     * @return This is used to configure the shape of the driver or executor if a flexible shape is used.
     * 
     */
    private List<GetSqlEndpointExecutorShapeConfig> executorShapeConfigs;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The provision identifier that is immutable on creation.
     * 
     */
    private String id;
    /**
     * @return The JDBC URL field. For example, jdbc:spark://{serviceFQDN}:443/default;SparkServerType=DFI
     * 
     */
    private String jdbcEndpointUrl;
    /**
     * @return The OCID of Oracle Cloud Infrastructure Lake.
     * 
     */
    private String lakeId;
    /**
     * @return The maximum number of executors.
     * 
     */
    private Integer maxExecutorCount;
    /**
     * @return The OCID of Oracle Cloud Infrastructure Hive Metastore.
     * 
     */
    private String metastoreId;
    /**
     * @return The minimum number of executors.
     * 
     */
    private Integer minExecutorCount;
    /**
     * @return The network configuration of a SQL Endpoint.
     * 
     */
    private List<GetSqlEndpointNetworkConfiguration> networkConfigurations;
    /**
     * @return The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { &#34;spark.app.name&#34; : &#34;My App Name&#34;, &#34;spark.shuffle.io.maxRetries&#34; : &#34;4&#34; } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
     * 
     */
    private Map<String,String> sparkAdvancedConfigurations;
    private String sqlEndpointId;
    /**
     * @return The version of SQL Endpoint.
     * 
     */
    private String sqlEndpointVersion;
    /**
     * @return The current state of the Sql Endpoint.
     * 
     */
    private String state;
    /**
     * @return A message describing the reason why the resource is in it&#39;s current state. Helps bubble up errors in state changes. For example, it can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    private String stateMessage;
    /**
     * @return The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The time the Sql Endpoint was created. An RFC3339 formatted datetime string.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the Sql Endpoint was updated. An RFC3339 formatted datetime string.
     * 
     */
    private String timeUpdated;
    /**
     * @return The warehouse bucket URI. It is a Oracle Cloud Infrastructure Object Storage bucket URI as defined here https://docs.oracle.com/en/cloud/paas/atp-cloud/atpud/object-storage-uris.html
     * 
     */
    private String warehouseBucketUri;

    private GetSqlEndpointResult() {}
    /**
     * @return The OCID of a compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description of the SQL Endpoint.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The SQL Endpoint name, which can be changed.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The shape of the SQL Endpoint driver instance.
     * 
     */
    public String driverShape() {
        return this.driverShape;
    }
    /**
     * @return This is used to configure the shape of the driver or executor if a flexible shape is used.
     * 
     */
    public List<GetSqlEndpointDriverShapeConfig> driverShapeConfigs() {
        return this.driverShapeConfigs;
    }
    /**
     * @return The shape of the SQL Endpoint executor instance.
     * 
     */
    public String executorShape() {
        return this.executorShape;
    }
    /**
     * @return This is used to configure the shape of the driver or executor if a flexible shape is used.
     * 
     */
    public List<GetSqlEndpointExecutorShapeConfig> executorShapeConfigs() {
        return this.executorShapeConfigs;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The provision identifier that is immutable on creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The JDBC URL field. For example, jdbc:spark://{serviceFQDN}:443/default;SparkServerType=DFI
     * 
     */
    public String jdbcEndpointUrl() {
        return this.jdbcEndpointUrl;
    }
    /**
     * @return The OCID of Oracle Cloud Infrastructure Lake.
     * 
     */
    public String lakeId() {
        return this.lakeId;
    }
    /**
     * @return The maximum number of executors.
     * 
     */
    public Integer maxExecutorCount() {
        return this.maxExecutorCount;
    }
    /**
     * @return The OCID of Oracle Cloud Infrastructure Hive Metastore.
     * 
     */
    public String metastoreId() {
        return this.metastoreId;
    }
    /**
     * @return The minimum number of executors.
     * 
     */
    public Integer minExecutorCount() {
        return this.minExecutorCount;
    }
    /**
     * @return The network configuration of a SQL Endpoint.
     * 
     */
    public List<GetSqlEndpointNetworkConfiguration> networkConfigurations() {
        return this.networkConfigurations;
    }
    /**
     * @return The Spark configuration passed to the running process. See https://spark.apache.org/docs/latest/configuration.html#available-properties. Example: { &#34;spark.app.name&#34; : &#34;My App Name&#34;, &#34;spark.shuffle.io.maxRetries&#34; : &#34;4&#34; } Note: Not all Spark properties are permitted to be set.  Attempting to set a property that is not allowed to be overwritten will cause a 400 status to be returned.
     * 
     */
    public Map<String,String> sparkAdvancedConfigurations() {
        return this.sparkAdvancedConfigurations;
    }
    public String sqlEndpointId() {
        return this.sqlEndpointId;
    }
    /**
     * @return The version of SQL Endpoint.
     * 
     */
    public String sqlEndpointVersion() {
        return this.sqlEndpointVersion;
    }
    /**
     * @return The current state of the Sql Endpoint.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return A message describing the reason why the resource is in it&#39;s current state. Helps bubble up errors in state changes. For example, it can be used to provide actionable information for a resource in the Failed state.
     * 
     */
    public String stateMessage() {
        return this.stateMessage;
    }
    /**
     * @return The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time the Sql Endpoint was created. An RFC3339 formatted datetime string.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the Sql Endpoint was updated. An RFC3339 formatted datetime string.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return The warehouse bucket URI. It is a Oracle Cloud Infrastructure Object Storage bucket URI as defined here https://docs.oracle.com/en/cloud/paas/atp-cloud/atpud/object-storage-uris.html
     * 
     */
    public String warehouseBucketUri() {
        return this.warehouseBucketUri;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSqlEndpointResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Map<String,String> definedTags;
        private String description;
        private String displayName;
        private String driverShape;
        private List<GetSqlEndpointDriverShapeConfig> driverShapeConfigs;
        private String executorShape;
        private List<GetSqlEndpointExecutorShapeConfig> executorShapeConfigs;
        private Map<String,String> freeformTags;
        private String id;
        private String jdbcEndpointUrl;
        private String lakeId;
        private Integer maxExecutorCount;
        private String metastoreId;
        private Integer minExecutorCount;
        private List<GetSqlEndpointNetworkConfiguration> networkConfigurations;
        private Map<String,String> sparkAdvancedConfigurations;
        private String sqlEndpointId;
        private String sqlEndpointVersion;
        private String state;
        private String stateMessage;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String warehouseBucketUri;
        public Builder() {}
        public Builder(GetSqlEndpointResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.driverShape = defaults.driverShape;
    	      this.driverShapeConfigs = defaults.driverShapeConfigs;
    	      this.executorShape = defaults.executorShape;
    	      this.executorShapeConfigs = defaults.executorShapeConfigs;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.jdbcEndpointUrl = defaults.jdbcEndpointUrl;
    	      this.lakeId = defaults.lakeId;
    	      this.maxExecutorCount = defaults.maxExecutorCount;
    	      this.metastoreId = defaults.metastoreId;
    	      this.minExecutorCount = defaults.minExecutorCount;
    	      this.networkConfigurations = defaults.networkConfigurations;
    	      this.sparkAdvancedConfigurations = defaults.sparkAdvancedConfigurations;
    	      this.sqlEndpointId = defaults.sqlEndpointId;
    	      this.sqlEndpointVersion = defaults.sqlEndpointVersion;
    	      this.state = defaults.state;
    	      this.stateMessage = defaults.stateMessage;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.warehouseBucketUri = defaults.warehouseBucketUri;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder driverShape(String driverShape) {
            if (driverShape == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "driverShape");
            }
            this.driverShape = driverShape;
            return this;
        }
        @CustomType.Setter
        public Builder driverShapeConfigs(List<GetSqlEndpointDriverShapeConfig> driverShapeConfigs) {
            if (driverShapeConfigs == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "driverShapeConfigs");
            }
            this.driverShapeConfigs = driverShapeConfigs;
            return this;
        }
        public Builder driverShapeConfigs(GetSqlEndpointDriverShapeConfig... driverShapeConfigs) {
            return driverShapeConfigs(List.of(driverShapeConfigs));
        }
        @CustomType.Setter
        public Builder executorShape(String executorShape) {
            if (executorShape == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "executorShape");
            }
            this.executorShape = executorShape;
            return this;
        }
        @CustomType.Setter
        public Builder executorShapeConfigs(List<GetSqlEndpointExecutorShapeConfig> executorShapeConfigs) {
            if (executorShapeConfigs == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "executorShapeConfigs");
            }
            this.executorShapeConfigs = executorShapeConfigs;
            return this;
        }
        public Builder executorShapeConfigs(GetSqlEndpointExecutorShapeConfig... executorShapeConfigs) {
            return executorShapeConfigs(List.of(executorShapeConfigs));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder jdbcEndpointUrl(String jdbcEndpointUrl) {
            if (jdbcEndpointUrl == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "jdbcEndpointUrl");
            }
            this.jdbcEndpointUrl = jdbcEndpointUrl;
            return this;
        }
        @CustomType.Setter
        public Builder lakeId(String lakeId) {
            if (lakeId == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "lakeId");
            }
            this.lakeId = lakeId;
            return this;
        }
        @CustomType.Setter
        public Builder maxExecutorCount(Integer maxExecutorCount) {
            if (maxExecutorCount == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "maxExecutorCount");
            }
            this.maxExecutorCount = maxExecutorCount;
            return this;
        }
        @CustomType.Setter
        public Builder metastoreId(String metastoreId) {
            if (metastoreId == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "metastoreId");
            }
            this.metastoreId = metastoreId;
            return this;
        }
        @CustomType.Setter
        public Builder minExecutorCount(Integer minExecutorCount) {
            if (minExecutorCount == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "minExecutorCount");
            }
            this.minExecutorCount = minExecutorCount;
            return this;
        }
        @CustomType.Setter
        public Builder networkConfigurations(List<GetSqlEndpointNetworkConfiguration> networkConfigurations) {
            if (networkConfigurations == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "networkConfigurations");
            }
            this.networkConfigurations = networkConfigurations;
            return this;
        }
        public Builder networkConfigurations(GetSqlEndpointNetworkConfiguration... networkConfigurations) {
            return networkConfigurations(List.of(networkConfigurations));
        }
        @CustomType.Setter
        public Builder sparkAdvancedConfigurations(Map<String,String> sparkAdvancedConfigurations) {
            if (sparkAdvancedConfigurations == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "sparkAdvancedConfigurations");
            }
            this.sparkAdvancedConfigurations = sparkAdvancedConfigurations;
            return this;
        }
        @CustomType.Setter
        public Builder sqlEndpointId(String sqlEndpointId) {
            if (sqlEndpointId == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "sqlEndpointId");
            }
            this.sqlEndpointId = sqlEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder sqlEndpointVersion(String sqlEndpointVersion) {
            if (sqlEndpointVersion == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "sqlEndpointVersion");
            }
            this.sqlEndpointVersion = sqlEndpointVersion;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder stateMessage(String stateMessage) {
            if (stateMessage == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "stateMessage");
            }
            this.stateMessage = stateMessage;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder warehouseBucketUri(String warehouseBucketUri) {
            if (warehouseBucketUri == null) {
              throw new MissingRequiredPropertyException("GetSqlEndpointResult", "warehouseBucketUri");
            }
            this.warehouseBucketUri = warehouseBucketUri;
            return this;
        }
        public GetSqlEndpointResult build() {
            final var _resultValue = new GetSqlEndpointResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.displayName = displayName;
            _resultValue.driverShape = driverShape;
            _resultValue.driverShapeConfigs = driverShapeConfigs;
            _resultValue.executorShape = executorShape;
            _resultValue.executorShapeConfigs = executorShapeConfigs;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.jdbcEndpointUrl = jdbcEndpointUrl;
            _resultValue.lakeId = lakeId;
            _resultValue.maxExecutorCount = maxExecutorCount;
            _resultValue.metastoreId = metastoreId;
            _resultValue.minExecutorCount = minExecutorCount;
            _resultValue.networkConfigurations = networkConfigurations;
            _resultValue.sparkAdvancedConfigurations = sparkAdvancedConfigurations;
            _resultValue.sqlEndpointId = sqlEndpointId;
            _resultValue.sqlEndpointVersion = sqlEndpointVersion;
            _resultValue.state = state;
            _resultValue.stateMessage = stateMessage;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.warehouseBucketUri = warehouseBucketUri;
            return _resultValue;
        }
    }
}
