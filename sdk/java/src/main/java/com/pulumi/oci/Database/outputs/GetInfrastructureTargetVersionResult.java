// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetInfrastructureTargetVersionResult {
    private String compartmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The history entry of the target system software version for the database server patching operation.
     * 
     */
    private List<String> targetDbVersionHistoryEntries;
    /**
     * @return The OCID of the target Exadata Infrastructure resource that will receive the maintenance update.
     * 
     */
    private @Nullable String targetResourceId;
    /**
     * @return The resource type of the target Exadata infrastructure resource that will receive the system software update.
     * 
     */
    private @Nullable String targetResourceType;
    /**
     * @return The history entry of the target storage cell system software version for the storage cell patching operation.
     * 
     */
    private List<String> targetStorageVersionHistoryEntries;

    private GetInfrastructureTargetVersionResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The history entry of the target system software version for the database server patching operation.
     * 
     */
    public List<String> targetDbVersionHistoryEntries() {
        return this.targetDbVersionHistoryEntries;
    }
    /**
     * @return The OCID of the target Exadata Infrastructure resource that will receive the maintenance update.
     * 
     */
    public Optional<String> targetResourceId() {
        return Optional.ofNullable(this.targetResourceId);
    }
    /**
     * @return The resource type of the target Exadata infrastructure resource that will receive the system software update.
     * 
     */
    public Optional<String> targetResourceType() {
        return Optional.ofNullable(this.targetResourceType);
    }
    /**
     * @return The history entry of the target storage cell system software version for the storage cell patching operation.
     * 
     */
    public List<String> targetStorageVersionHistoryEntries() {
        return this.targetStorageVersionHistoryEntries;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInfrastructureTargetVersionResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private String id;
        private List<String> targetDbVersionHistoryEntries;
        private @Nullable String targetResourceId;
        private @Nullable String targetResourceType;
        private List<String> targetStorageVersionHistoryEntries;
        public Builder() {}
        public Builder(GetInfrastructureTargetVersionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.targetDbVersionHistoryEntries = defaults.targetDbVersionHistoryEntries;
    	      this.targetResourceId = defaults.targetResourceId;
    	      this.targetResourceType = defaults.targetResourceType;
    	      this.targetStorageVersionHistoryEntries = defaults.targetStorageVersionHistoryEntries;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder targetDbVersionHistoryEntries(List<String> targetDbVersionHistoryEntries) {
            this.targetDbVersionHistoryEntries = Objects.requireNonNull(targetDbVersionHistoryEntries);
            return this;
        }
        public Builder targetDbVersionHistoryEntries(String... targetDbVersionHistoryEntries) {
            return targetDbVersionHistoryEntries(List.of(targetDbVersionHistoryEntries));
        }
        @CustomType.Setter
        public Builder targetResourceId(@Nullable String targetResourceId) {
            this.targetResourceId = targetResourceId;
            return this;
        }
        @CustomType.Setter
        public Builder targetResourceType(@Nullable String targetResourceType) {
            this.targetResourceType = targetResourceType;
            return this;
        }
        @CustomType.Setter
        public Builder targetStorageVersionHistoryEntries(List<String> targetStorageVersionHistoryEntries) {
            this.targetStorageVersionHistoryEntries = Objects.requireNonNull(targetStorageVersionHistoryEntries);
            return this;
        }
        public Builder targetStorageVersionHistoryEntries(String... targetStorageVersionHistoryEntries) {
            return targetStorageVersionHistoryEntries(List.of(targetStorageVersionHistoryEntries));
        }
        public GetInfrastructureTargetVersionResult build() {
            final var o = new GetInfrastructureTargetVersionResult();
            o.compartmentId = compartmentId;
            o.id = id;
            o.targetDbVersionHistoryEntries = targetDbVersionHistoryEntries;
            o.targetResourceId = targetResourceId;
            o.targetResourceType = targetResourceType;
            o.targetStorageVersionHistoryEntries = targetStorageVersionHistoryEntries;
            return o;
        }
    }
}