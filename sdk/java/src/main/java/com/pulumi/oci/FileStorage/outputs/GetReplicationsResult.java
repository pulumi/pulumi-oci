// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.FileStorage.outputs.GetReplicationsFilter;
import com.pulumi.oci.FileStorage.outputs.GetReplicationsReplication;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetReplicationsResult {
    /**
     * @return The availability domain the replication is in. The replication must be in the same availability domain as the source file system. Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My replication`
     * 
     */
    private @Nullable String displayName;
    private @Nullable String fileSystemId;
    private @Nullable List<GetReplicationsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the replication.
     * 
     */
    private @Nullable String id;
    /**
     * @return The list of replications.
     * 
     */
    private List<GetReplicationsReplication> replications;
    /**
     * @return The current state of this replication. This resource can be in a `FAILED` state if replication target is deleted instead of the replication resource.
     * 
     */
    private @Nullable String state;

    private GetReplicationsResult() {}
    /**
     * @return The availability domain the replication is in. The replication must be in the same availability domain as the source file system. Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My replication`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public Optional<String> fileSystemId() {
        return Optional.ofNullable(this.fileSystemId);
    }
    public List<GetReplicationsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the replication.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The list of replications.
     * 
     */
    public List<GetReplicationsReplication> replications() {
        return this.replications;
    }
    /**
     * @return The current state of this replication. This resource can be in a `FAILED` state if replication target is deleted instead of the replication resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetReplicationsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable String fileSystemId;
        private @Nullable List<GetReplicationsFilter> filters;
        private @Nullable String id;
        private List<GetReplicationsReplication> replications;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetReplicationsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.fileSystemId = defaults.fileSystemId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.replications = defaults.replications;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder fileSystemId(@Nullable String fileSystemId) {
            this.fileSystemId = fileSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetReplicationsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetReplicationsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder replications(List<GetReplicationsReplication> replications) {
            this.replications = Objects.requireNonNull(replications);
            return this;
        }
        public Builder replications(GetReplicationsReplication... replications) {
            return replications(List.of(replications));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetReplicationsResult build() {
            final var o = new GetReplicationsResult();
            o.availabilityDomain = availabilityDomain;
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.fileSystemId = fileSystemId;
            o.filters = filters;
            o.id = id;
            o.replications = replications;
            o.state = state;
            return o;
        }
    }
}