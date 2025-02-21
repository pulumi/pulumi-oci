// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Opsi.outputs.ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetails;
import com.pulumi.oci.Opsi.outputs.ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetails;
import com.pulumi.oci.Opsi.outputs.ExadataInsightMemberVmClusterDetailMemberDatabaseDetailCredentialDetails;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExadataInsightMemberVmClusterDetailMemberDatabaseDetail {
    /**
     * @return (Updatable) Compartment Identifier of database
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return User credential details to connect to the database.
     * 
     */
    private @Nullable ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetails connectionCredentialDetails;
    /**
     * @return Connection details to connect to the database. HostName, protocol, and port should be specified.
     * 
     */
    private @Nullable ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetails connectionDetails;
    /**
     * @return User credential details to connect to the database.
     * 
     */
    private @Nullable ExadataInsightMemberVmClusterDetailMemberDatabaseDetailCredentialDetails credentialDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    private @Nullable String databaseId;
    /**
     * @return Oracle Cloud Infrastructure database resource type
     * 
     */
    private @Nullable String databaseResourceType;
    private @Nullable String dbmPrivateEndpointId;
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,String> definedTags;
    /**
     * @return Database Deployment Type (EXACS will be supported in the future)
     * 
     */
    private @Nullable String deploymentType;
    /**
     * @return (Updatable) Source of the Exadata system.
     * 
     */
    private @Nullable String entitySource;
    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Management Agent
     * 
     */
    private @Nullable String managementAgentId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OPSI private endpoint
     * 
     */
    private @Nullable String opsiPrivateEndpointId;
    private @Nullable String serviceName;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private @Nullable Map<String,String> systemTags;

    private ExadataInsightMemberVmClusterDetailMemberDatabaseDetail() {}
    /**
     * @return (Updatable) Compartment Identifier of database
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return User credential details to connect to the database.
     * 
     */
    public Optional<ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetails> connectionCredentialDetails() {
        return Optional.ofNullable(this.connectionCredentialDetails);
    }
    /**
     * @return Connection details to connect to the database. HostName, protocol, and port should be specified.
     * 
     */
    public Optional<ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetails> connectionDetails() {
        return Optional.ofNullable(this.connectionDetails);
    }
    /**
     * @return User credential details to connect to the database.
     * 
     */
    public Optional<ExadataInsightMemberVmClusterDetailMemberDatabaseDetailCredentialDetails> credentialDetails() {
        return Optional.ofNullable(this.credentialDetails);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    public Optional<String> databaseId() {
        return Optional.ofNullable(this.databaseId);
    }
    /**
     * @return Oracle Cloud Infrastructure database resource type
     * 
     */
    public Optional<String> databaseResourceType() {
        return Optional.ofNullable(this.databaseResourceType);
    }
    public Optional<String> dbmPrivateEndpointId() {
        return Optional.ofNullable(this.dbmPrivateEndpointId);
    }
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags == null ? Map.of() : this.definedTags;
    }
    /**
     * @return Database Deployment Type (EXACS will be supported in the future)
     * 
     */
    public Optional<String> deploymentType() {
        return Optional.ofNullable(this.deploymentType);
    }
    /**
     * @return (Updatable) Source of the Exadata system.
     * 
     */
    public Optional<String> entitySource() {
        return Optional.ofNullable(this.entitySource);
    }
    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags == null ? Map.of() : this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Management Agent
     * 
     */
    public Optional<String> managementAgentId() {
        return Optional.ofNullable(this.managementAgentId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OPSI private endpoint
     * 
     */
    public Optional<String> opsiPrivateEndpointId() {
        return Optional.ofNullable(this.opsiPrivateEndpointId);
    }
    public Optional<String> serviceName() {
        return Optional.ofNullable(this.serviceName);
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags == null ? Map.of() : this.systemTags;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExadataInsightMemberVmClusterDetailMemberDatabaseDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetails connectionCredentialDetails;
        private @Nullable ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetails connectionDetails;
        private @Nullable ExadataInsightMemberVmClusterDetailMemberDatabaseDetailCredentialDetails credentialDetails;
        private @Nullable String databaseId;
        private @Nullable String databaseResourceType;
        private @Nullable String dbmPrivateEndpointId;
        private @Nullable Map<String,String> definedTags;
        private @Nullable String deploymentType;
        private @Nullable String entitySource;
        private @Nullable Map<String,String> freeformTags;
        private @Nullable String managementAgentId;
        private @Nullable String opsiPrivateEndpointId;
        private @Nullable String serviceName;
        private @Nullable Map<String,String> systemTags;
        public Builder() {}
        public Builder(ExadataInsightMemberVmClusterDetailMemberDatabaseDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.connectionCredentialDetails = defaults.connectionCredentialDetails;
    	      this.connectionDetails = defaults.connectionDetails;
    	      this.credentialDetails = defaults.credentialDetails;
    	      this.databaseId = defaults.databaseId;
    	      this.databaseResourceType = defaults.databaseResourceType;
    	      this.dbmPrivateEndpointId = defaults.dbmPrivateEndpointId;
    	      this.definedTags = defaults.definedTags;
    	      this.deploymentType = defaults.deploymentType;
    	      this.entitySource = defaults.entitySource;
    	      this.freeformTags = defaults.freeformTags;
    	      this.managementAgentId = defaults.managementAgentId;
    	      this.opsiPrivateEndpointId = defaults.opsiPrivateEndpointId;
    	      this.serviceName = defaults.serviceName;
    	      this.systemTags = defaults.systemTags;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder connectionCredentialDetails(@Nullable ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetails connectionCredentialDetails) {

            this.connectionCredentialDetails = connectionCredentialDetails;
            return this;
        }
        @CustomType.Setter
        public Builder connectionDetails(@Nullable ExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetails connectionDetails) {

            this.connectionDetails = connectionDetails;
            return this;
        }
        @CustomType.Setter
        public Builder credentialDetails(@Nullable ExadataInsightMemberVmClusterDetailMemberDatabaseDetailCredentialDetails credentialDetails) {

            this.credentialDetails = credentialDetails;
            return this;
        }
        @CustomType.Setter
        public Builder databaseId(@Nullable String databaseId) {

            this.databaseId = databaseId;
            return this;
        }
        @CustomType.Setter
        public Builder databaseResourceType(@Nullable String databaseResourceType) {

            this.databaseResourceType = databaseResourceType;
            return this;
        }
        @CustomType.Setter
        public Builder dbmPrivateEndpointId(@Nullable String dbmPrivateEndpointId) {

            this.dbmPrivateEndpointId = dbmPrivateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(@Nullable Map<String,String> definedTags) {

            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder deploymentType(@Nullable String deploymentType) {

            this.deploymentType = deploymentType;
            return this;
        }
        @CustomType.Setter
        public Builder entitySource(@Nullable String entitySource) {

            this.entitySource = entitySource;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(@Nullable Map<String,String> freeformTags) {

            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder managementAgentId(@Nullable String managementAgentId) {

            this.managementAgentId = managementAgentId;
            return this;
        }
        @CustomType.Setter
        public Builder opsiPrivateEndpointId(@Nullable String opsiPrivateEndpointId) {

            this.opsiPrivateEndpointId = opsiPrivateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder serviceName(@Nullable String serviceName) {

            this.serviceName = serviceName;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(@Nullable Map<String,String> systemTags) {

            this.systemTags = systemTags;
            return this;
        }
        public ExadataInsightMemberVmClusterDetailMemberDatabaseDetail build() {
            final var _resultValue = new ExadataInsightMemberVmClusterDetailMemberDatabaseDetail();
            _resultValue.compartmentId = compartmentId;
            _resultValue.connectionCredentialDetails = connectionCredentialDetails;
            _resultValue.connectionDetails = connectionDetails;
            _resultValue.credentialDetails = credentialDetails;
            _resultValue.databaseId = databaseId;
            _resultValue.databaseResourceType = databaseResourceType;
            _resultValue.dbmPrivateEndpointId = dbmPrivateEndpointId;
            _resultValue.definedTags = definedTags;
            _resultValue.deploymentType = deploymentType;
            _resultValue.entitySource = entitySource;
            _resultValue.freeformTags = freeformTags;
            _resultValue.managementAgentId = managementAgentId;
            _resultValue.opsiPrivateEndpointId = opsiPrivateEndpointId;
            _resultValue.serviceName = serviceName;
            _resultValue.systemTags = systemTags;
            return _resultValue;
        }
    }
}
