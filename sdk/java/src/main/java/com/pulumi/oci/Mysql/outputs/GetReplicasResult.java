// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Mysql.outputs.GetReplicasFilter;
import com.pulumi.oci.Mysql.outputs.GetReplicasReplica;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetReplicasResult {
    /**
     * @return The OCID of the compartment that contains the read replica.
     * 
     */
    private String compartmentId;
    /**
     * @return The OCID of the Configuration to be used by the read replica.
     * 
     */
    private @Nullable String configurationId;
    /**
     * @return The OCID of the DB System the read replica is associated with.
     * 
     */
    private @Nullable String dbSystemId;
    /**
     * @return The user-friendly name for the read replica. It does not have to be unique.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetReplicasFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable Boolean isUpToDate;
    private @Nullable String replicaId;
    /**
     * @return The list of replicas.
     * 
     */
    private List<GetReplicasReplica> replicas;
    /**
     * @return The state of the read replica.
     * 
     */
    private @Nullable String state;

    private GetReplicasResult() {}
    /**
     * @return The OCID of the compartment that contains the read replica.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The OCID of the Configuration to be used by the read replica.
     * 
     */
    public Optional<String> configurationId() {
        return Optional.ofNullable(this.configurationId);
    }
    /**
     * @return The OCID of the DB System the read replica is associated with.
     * 
     */
    public Optional<String> dbSystemId() {
        return Optional.ofNullable(this.dbSystemId);
    }
    /**
     * @return The user-friendly name for the read replica. It does not have to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetReplicasFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<Boolean> isUpToDate() {
        return Optional.ofNullable(this.isUpToDate);
    }
    public Optional<String> replicaId() {
        return Optional.ofNullable(this.replicaId);
    }
    /**
     * @return The list of replicas.
     * 
     */
    public List<GetReplicasReplica> replicas() {
        return this.replicas;
    }
    /**
     * @return The state of the read replica.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetReplicasResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String configurationId;
        private @Nullable String dbSystemId;
        private @Nullable String displayName;
        private @Nullable List<GetReplicasFilter> filters;
        private String id;
        private @Nullable Boolean isUpToDate;
        private @Nullable String replicaId;
        private List<GetReplicasReplica> replicas;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetReplicasResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.configurationId = defaults.configurationId;
    	      this.dbSystemId = defaults.dbSystemId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.isUpToDate = defaults.isUpToDate;
    	      this.replicaId = defaults.replicaId;
    	      this.replicas = defaults.replicas;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetReplicasResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder configurationId(@Nullable String configurationId) {

            this.configurationId = configurationId;
            return this;
        }
        @CustomType.Setter
        public Builder dbSystemId(@Nullable String dbSystemId) {

            this.dbSystemId = dbSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetReplicasFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetReplicasFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetReplicasResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isUpToDate(@Nullable Boolean isUpToDate) {

            this.isUpToDate = isUpToDate;
            return this;
        }
        @CustomType.Setter
        public Builder replicaId(@Nullable String replicaId) {

            this.replicaId = replicaId;
            return this;
        }
        @CustomType.Setter
        public Builder replicas(List<GetReplicasReplica> replicas) {
            if (replicas == null) {
              throw new MissingRequiredPropertyException("GetReplicasResult", "replicas");
            }
            this.replicas = replicas;
            return this;
        }
        public Builder replicas(GetReplicasReplica... replicas) {
            return replicas(List.of(replicas));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetReplicasResult build() {
            final var _resultValue = new GetReplicasResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.configurationId = configurationId;
            _resultValue.dbSystemId = dbSystemId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.isUpToDate = isUpToDate;
            _resultValue.replicaId = replicaId;
            _resultValue.replicas = replicas;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
