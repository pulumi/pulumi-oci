// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabase;
import com.pulumi.oci.Database.outputs.GetAutonomousContainerDatabasesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetAutonomousContainerDatabasesResult {
    /**
     * @return The list of autonomous_container_databases.
     * 
     */
    private final List<GetAutonomousContainerDatabasesAutonomousContainerDatabase> autonomousContainerDatabases;
    /**
     * @return The OCID of the Autonomous Exadata Infrastructure.
     * 
     */
    private final @Nullable String autonomousExadataInfrastructureId;
    /**
     * @return The OCID of the Autonomous VM Cluster.
     * 
     */
    private final @Nullable String autonomousVmClusterId;
    /**
     * @return The availability domain of the Autonomous Container Database.
     * 
     */
    private final @Nullable String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Autonomous Exadata VM Cluster.
     * 
     */
    private final @Nullable String cloudAutonomousVmClusterId;
    /**
     * @return The OCID of the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return The user-provided name for the Autonomous Container Database.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetAutonomousContainerDatabasesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The infrastructure type this resource belongs to.
     * 
     */
    private final @Nullable String infrastructureType;
    /**
     * @return The service level agreement type of the container database. The default is STANDARD.
     * 
     */
    private final @Nullable String serviceLevelAgreementType;
    /**
     * @return The current state of the Autonomous Container Database.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetAutonomousContainerDatabasesResult(
        @CustomType.Parameter("autonomousContainerDatabases") List<GetAutonomousContainerDatabasesAutonomousContainerDatabase> autonomousContainerDatabases,
        @CustomType.Parameter("autonomousExadataInfrastructureId") @Nullable String autonomousExadataInfrastructureId,
        @CustomType.Parameter("autonomousVmClusterId") @Nullable String autonomousVmClusterId,
        @CustomType.Parameter("availabilityDomain") @Nullable String availabilityDomain,
        @CustomType.Parameter("cloudAutonomousVmClusterId") @Nullable String cloudAutonomousVmClusterId,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetAutonomousContainerDatabasesFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("infrastructureType") @Nullable String infrastructureType,
        @CustomType.Parameter("serviceLevelAgreementType") @Nullable String serviceLevelAgreementType,
        @CustomType.Parameter("state") @Nullable String state) {
        this.autonomousContainerDatabases = autonomousContainerDatabases;
        this.autonomousExadataInfrastructureId = autonomousExadataInfrastructureId;
        this.autonomousVmClusterId = autonomousVmClusterId;
        this.availabilityDomain = availabilityDomain;
        this.cloudAutonomousVmClusterId = cloudAutonomousVmClusterId;
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.infrastructureType = infrastructureType;
        this.serviceLevelAgreementType = serviceLevelAgreementType;
        this.state = state;
    }

    /**
     * @return The list of autonomous_container_databases.
     * 
     */
    public List<GetAutonomousContainerDatabasesAutonomousContainerDatabase> autonomousContainerDatabases() {
        return this.autonomousContainerDatabases;
    }
    /**
     * @return The OCID of the Autonomous Exadata Infrastructure.
     * 
     */
    public Optional<String> autonomousExadataInfrastructureId() {
        return Optional.ofNullable(this.autonomousExadataInfrastructureId);
    }
    /**
     * @return The OCID of the Autonomous VM Cluster.
     * 
     */
    public Optional<String> autonomousVmClusterId() {
        return Optional.ofNullable(this.autonomousVmClusterId);
    }
    /**
     * @return The availability domain of the Autonomous Container Database.
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Autonomous Exadata VM Cluster.
     * 
     */
    public Optional<String> cloudAutonomousVmClusterId() {
        return Optional.ofNullable(this.cloudAutonomousVmClusterId);
    }
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The user-provided name for the Autonomous Container Database.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetAutonomousContainerDatabasesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The infrastructure type this resource belongs to.
     * 
     */
    public Optional<String> infrastructureType() {
        return Optional.ofNullable(this.infrastructureType);
    }
    /**
     * @return The service level agreement type of the container database. The default is STANDARD.
     * 
     */
    public Optional<String> serviceLevelAgreementType() {
        return Optional.ofNullable(this.serviceLevelAgreementType);
    }
    /**
     * @return The current state of the Autonomous Container Database.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousContainerDatabasesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetAutonomousContainerDatabasesAutonomousContainerDatabase> autonomousContainerDatabases;
        private @Nullable String autonomousExadataInfrastructureId;
        private @Nullable String autonomousVmClusterId;
        private @Nullable String availabilityDomain;
        private @Nullable String cloudAutonomousVmClusterId;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetAutonomousContainerDatabasesFilter> filters;
        private String id;
        private @Nullable String infrastructureType;
        private @Nullable String serviceLevelAgreementType;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAutonomousContainerDatabasesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autonomousContainerDatabases = defaults.autonomousContainerDatabases;
    	      this.autonomousExadataInfrastructureId = defaults.autonomousExadataInfrastructureId;
    	      this.autonomousVmClusterId = defaults.autonomousVmClusterId;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.cloudAutonomousVmClusterId = defaults.cloudAutonomousVmClusterId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.infrastructureType = defaults.infrastructureType;
    	      this.serviceLevelAgreementType = defaults.serviceLevelAgreementType;
    	      this.state = defaults.state;
        }

        public Builder autonomousContainerDatabases(List<GetAutonomousContainerDatabasesAutonomousContainerDatabase> autonomousContainerDatabases) {
            this.autonomousContainerDatabases = Objects.requireNonNull(autonomousContainerDatabases);
            return this;
        }
        public Builder autonomousContainerDatabases(GetAutonomousContainerDatabasesAutonomousContainerDatabase... autonomousContainerDatabases) {
            return autonomousContainerDatabases(List.of(autonomousContainerDatabases));
        }
        public Builder autonomousExadataInfrastructureId(@Nullable String autonomousExadataInfrastructureId) {
            this.autonomousExadataInfrastructureId = autonomousExadataInfrastructureId;
            return this;
        }
        public Builder autonomousVmClusterId(@Nullable String autonomousVmClusterId) {
            this.autonomousVmClusterId = autonomousVmClusterId;
            return this;
        }
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        public Builder cloudAutonomousVmClusterId(@Nullable String cloudAutonomousVmClusterId) {
            this.cloudAutonomousVmClusterId = cloudAutonomousVmClusterId;
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetAutonomousContainerDatabasesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetAutonomousContainerDatabasesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder infrastructureType(@Nullable String infrastructureType) {
            this.infrastructureType = infrastructureType;
            return this;
        }
        public Builder serviceLevelAgreementType(@Nullable String serviceLevelAgreementType) {
            this.serviceLevelAgreementType = serviceLevelAgreementType;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetAutonomousContainerDatabasesResult build() {
            return new GetAutonomousContainerDatabasesResult(autonomousContainerDatabases, autonomousExadataInfrastructureId, autonomousVmClusterId, availabilityDomain, cloudAutonomousVmClusterId, compartmentId, displayName, filters, id, infrastructureType, serviceLevelAgreementType, state);
        }
    }
}
