// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetLogAnalyticsEntitiesSummaryResult {
    /**
     * @return Total number of ACTIVE entities
     * 
     */
    private final Integer activeEntitiesCount;
    /**
     * @return Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private final String compartmentId;
    /**
     * @return Entities with log collection enabled
     * 
     */
    private final Integer entitiesWithHasLogsCollectedCount;
    /**
     * @return Entities with management agent
     * 
     */
    private final Integer entitiesWithManagementAgentCount;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String namespace;

    @CustomType.Constructor
    private GetLogAnalyticsEntitiesSummaryResult(
        @CustomType.Parameter("activeEntitiesCount") Integer activeEntitiesCount,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("entitiesWithHasLogsCollectedCount") Integer entitiesWithHasLogsCollectedCount,
        @CustomType.Parameter("entitiesWithManagementAgentCount") Integer entitiesWithManagementAgentCount,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("namespace") String namespace) {
        this.activeEntitiesCount = activeEntitiesCount;
        this.compartmentId = compartmentId;
        this.entitiesWithHasLogsCollectedCount = entitiesWithHasLogsCollectedCount;
        this.entitiesWithManagementAgentCount = entitiesWithManagementAgentCount;
        this.id = id;
        this.namespace = namespace;
    }

    /**
     * @return Total number of ACTIVE entities
     * 
     */
    public Integer activeEntitiesCount() {
        return this.activeEntitiesCount;
    }
    /**
     * @return Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Entities with log collection enabled
     * 
     */
    public Integer entitiesWithHasLogsCollectedCount() {
        return this.entitiesWithHasLogsCollectedCount;
    }
    /**
     * @return Entities with management agent
     * 
     */
    public Integer entitiesWithManagementAgentCount() {
        return this.entitiesWithManagementAgentCount;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String namespace() {
        return this.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogAnalyticsEntitiesSummaryResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer activeEntitiesCount;
        private String compartmentId;
        private Integer entitiesWithHasLogsCollectedCount;
        private Integer entitiesWithManagementAgentCount;
        private String id;
        private String namespace;

        public Builder() {
    	      // Empty
        }

        public Builder(GetLogAnalyticsEntitiesSummaryResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.activeEntitiesCount = defaults.activeEntitiesCount;
    	      this.compartmentId = defaults.compartmentId;
    	      this.entitiesWithHasLogsCollectedCount = defaults.entitiesWithHasLogsCollectedCount;
    	      this.entitiesWithManagementAgentCount = defaults.entitiesWithManagementAgentCount;
    	      this.id = defaults.id;
    	      this.namespace = defaults.namespace;
        }

        public Builder activeEntitiesCount(Integer activeEntitiesCount) {
            this.activeEntitiesCount = Objects.requireNonNull(activeEntitiesCount);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder entitiesWithHasLogsCollectedCount(Integer entitiesWithHasLogsCollectedCount) {
            this.entitiesWithHasLogsCollectedCount = Objects.requireNonNull(entitiesWithHasLogsCollectedCount);
            return this;
        }
        public Builder entitiesWithManagementAgentCount(Integer entitiesWithManagementAgentCount) {
            this.entitiesWithManagementAgentCount = Objects.requireNonNull(entitiesWithManagementAgentCount);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }        public GetLogAnalyticsEntitiesSummaryResult build() {
            return new GetLogAnalyticsEntitiesSummaryResult(activeEntitiesCount, compartmentId, entitiesWithHasLogsCollectedCount, entitiesWithManagementAgentCount, id, namespace);
        }
    }
}
