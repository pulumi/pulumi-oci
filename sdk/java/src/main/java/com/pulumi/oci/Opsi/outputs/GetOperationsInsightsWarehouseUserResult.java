// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetOperationsInsightsWarehouseUserResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return User provided connection password for the AWR Data,  Enterprise Manager Data and Operations Insights OPSI Hub.
     * 
     */
    private final String connectionPassword;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return Hub User OCID
     * 
     */
    private final String id;
    /**
     * @return Indicate whether user has access to AWR data.
     * 
     */
    private final Boolean isAwrDataAccess;
    /**
     * @return Indicate whether user has access to EM data.
     * 
     */
    private final Boolean isEmDataAccess;
    /**
     * @return Indicate whether user has access to OPSI data.
     * 
     */
    private final Boolean isOpsiDataAccess;
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    private final String lifecycleDetails;
    /**
     * @return Username for schema which would have access to AWR Data,  Enterprise Manager Data and Operations Insights OPSI Hub.
     * 
     */
    private final String name;
    /**
     * @return OPSI Warehouse OCID
     * 
     */
    private final String operationsInsightsWarehouseId;
    private final String operationsInsightsWarehouseUserId;
    /**
     * @return Possible lifecycle states
     * 
     */
    private final String state;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private final Map<String,Object> systemTags;
    /**
     * @return The time at which the resource was first created. An RFC3339 formatted datetime string
     * 
     */
    private final String timeCreated;
    /**
     * @return The time at which the resource was last updated. An RFC3339 formatted datetime string
     * 
     */
    private final String timeUpdated;

    @CustomType.Constructor
    private GetOperationsInsightsWarehouseUserResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("connectionPassword") String connectionPassword,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("isAwrDataAccess") Boolean isAwrDataAccess,
        @CustomType.Parameter("isEmDataAccess") Boolean isEmDataAccess,
        @CustomType.Parameter("isOpsiDataAccess") Boolean isOpsiDataAccess,
        @CustomType.Parameter("lifecycleDetails") String lifecycleDetails,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("operationsInsightsWarehouseId") String operationsInsightsWarehouseId,
        @CustomType.Parameter("operationsInsightsWarehouseUserId") String operationsInsightsWarehouseUserId,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("systemTags") Map<String,Object> systemTags,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("timeUpdated") String timeUpdated) {
        this.compartmentId = compartmentId;
        this.connectionPassword = connectionPassword;
        this.definedTags = definedTags;
        this.freeformTags = freeformTags;
        this.id = id;
        this.isAwrDataAccess = isAwrDataAccess;
        this.isEmDataAccess = isEmDataAccess;
        this.isOpsiDataAccess = isOpsiDataAccess;
        this.lifecycleDetails = lifecycleDetails;
        this.name = name;
        this.operationsInsightsWarehouseId = operationsInsightsWarehouseId;
        this.operationsInsightsWarehouseUserId = operationsInsightsWarehouseUserId;
        this.state = state;
        this.systemTags = systemTags;
        this.timeCreated = timeCreated;
        this.timeUpdated = timeUpdated;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return User provided connection password for the AWR Data,  Enterprise Manager Data and Operations Insights OPSI Hub.
     * 
     */
    public String connectionPassword() {
        return this.connectionPassword;
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
     * @return Hub User OCID
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicate whether user has access to AWR data.
     * 
     */
    public Boolean isAwrDataAccess() {
        return this.isAwrDataAccess;
    }
    /**
     * @return Indicate whether user has access to EM data.
     * 
     */
    public Boolean isEmDataAccess() {
        return this.isEmDataAccess;
    }
    /**
     * @return Indicate whether user has access to OPSI data.
     * 
     */
    public Boolean isOpsiDataAccess() {
        return this.isOpsiDataAccess;
    }
    /**
     * @return A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Username for schema which would have access to AWR Data,  Enterprise Manager Data and Operations Insights OPSI Hub.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return OPSI Warehouse OCID
     * 
     */
    public String operationsInsightsWarehouseId() {
        return this.operationsInsightsWarehouseId;
    }
    public String operationsInsightsWarehouseUserId() {
        return this.operationsInsightsWarehouseUserId;
    }
    /**
     * @return Possible lifecycle states
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time at which the resource was first created. An RFC3339 formatted datetime string
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time at which the resource was last updated. An RFC3339 formatted datetime string
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOperationsInsightsWarehouseUserResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private String connectionPassword;
        private Map<String,Object> definedTags;
        private Map<String,Object> freeformTags;
        private String id;
        private Boolean isAwrDataAccess;
        private Boolean isEmDataAccess;
        private Boolean isOpsiDataAccess;
        private String lifecycleDetails;
        private String name;
        private String operationsInsightsWarehouseId;
        private String operationsInsightsWarehouseUserId;
        private String state;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetOperationsInsightsWarehouseUserResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionPassword = defaults.connectionPassword;
    	      this.definedTags = defaults.definedTags;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isAwrDataAccess = defaults.isAwrDataAccess;
    	      this.isEmDataAccess = defaults.isEmDataAccess;
    	      this.isOpsiDataAccess = defaults.isOpsiDataAccess;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.name = defaults.name;
    	      this.operationsInsightsWarehouseId = defaults.operationsInsightsWarehouseId;
    	      this.operationsInsightsWarehouseUserId = defaults.operationsInsightsWarehouseUserId;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder connectionPassword(String connectionPassword) {
            this.connectionPassword = Objects.requireNonNull(connectionPassword);
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
        public Builder isAwrDataAccess(Boolean isAwrDataAccess) {
            this.isAwrDataAccess = Objects.requireNonNull(isAwrDataAccess);
            return this;
        }
        public Builder isEmDataAccess(Boolean isEmDataAccess) {
            this.isEmDataAccess = Objects.requireNonNull(isEmDataAccess);
            return this;
        }
        public Builder isOpsiDataAccess(Boolean isOpsiDataAccess) {
            this.isOpsiDataAccess = Objects.requireNonNull(isOpsiDataAccess);
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
        public Builder operationsInsightsWarehouseId(String operationsInsightsWarehouseId) {
            this.operationsInsightsWarehouseId = Objects.requireNonNull(operationsInsightsWarehouseId);
            return this;
        }
        public Builder operationsInsightsWarehouseUserId(String operationsInsightsWarehouseUserId) {
            this.operationsInsightsWarehouseUserId = Objects.requireNonNull(operationsInsightsWarehouseUserId);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }        public GetOperationsInsightsWarehouseUserResult build() {
            return new GetOperationsInsightsWarehouseUserResult(compartmentId, connectionPassword, definedTags, freeformTags, id, isAwrDataAccess, isEmDataAccess, isOpsiDataAccess, lifecycleDetails, name, operationsInsightsWarehouseId, operationsInsightsWarehouseUserId, state, systemTags, timeCreated, timeUpdated);
        }
    }
}
