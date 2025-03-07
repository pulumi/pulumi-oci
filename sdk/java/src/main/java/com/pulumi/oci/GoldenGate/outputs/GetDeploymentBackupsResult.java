// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GoldenGate.outputs.GetDeploymentBackupsDeploymentBackupCollection;
import com.pulumi.oci.GoldenGate.outputs.GetDeploymentBackupsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDeploymentBackupsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of deployment_backup_collection.
     * 
     */
    private List<GetDeploymentBackupsDeploymentBackupCollection> deploymentBackupCollections;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
     * 
     */
    private @Nullable String deploymentId;
    /**
     * @return An object&#39;s Display Name.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetDeploymentBackupsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Possible lifecycle states.
     * 
     */
    private @Nullable String state;

    private GetDeploymentBackupsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of deployment_backup_collection.
     * 
     */
    public List<GetDeploymentBackupsDeploymentBackupCollection> deploymentBackupCollections() {
        return this.deploymentBackupCollections;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
     * 
     */
    public Optional<String> deploymentId() {
        return Optional.ofNullable(this.deploymentId);
    }
    /**
     * @return An object&#39;s Display Name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetDeploymentBackupsFilter> filters() {
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
     * @return Possible lifecycle states.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentBackupsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetDeploymentBackupsDeploymentBackupCollection> deploymentBackupCollections;
        private @Nullable String deploymentId;
        private @Nullable String displayName;
        private @Nullable List<GetDeploymentBackupsFilter> filters;
        private String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetDeploymentBackupsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.deploymentBackupCollections = defaults.deploymentBackupCollections;
    	      this.deploymentId = defaults.deploymentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetDeploymentBackupsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder deploymentBackupCollections(List<GetDeploymentBackupsDeploymentBackupCollection> deploymentBackupCollections) {
            if (deploymentBackupCollections == null) {
              throw new MissingRequiredPropertyException("GetDeploymentBackupsResult", "deploymentBackupCollections");
            }
            this.deploymentBackupCollections = deploymentBackupCollections;
            return this;
        }
        public Builder deploymentBackupCollections(GetDeploymentBackupsDeploymentBackupCollection... deploymentBackupCollections) {
            return deploymentBackupCollections(List.of(deploymentBackupCollections));
        }
        @CustomType.Setter
        public Builder deploymentId(@Nullable String deploymentId) {

            this.deploymentId = deploymentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDeploymentBackupsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetDeploymentBackupsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDeploymentBackupsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetDeploymentBackupsResult build() {
            final var _resultValue = new GetDeploymentBackupsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.deploymentBackupCollections = deploymentBackupCollections;
            _resultValue.deploymentId = deploymentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
