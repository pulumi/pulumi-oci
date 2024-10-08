// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FileStorage.outputs.GetFileSystemsFileSystem;
import com.pulumi.oci.FileStorage.outputs.GetFileSystemsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFileSystemsResult {
    /**
     * @return The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the file system.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My file system`
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The list of file_systems.
     * 
     */
    private List<GetFileSystemsFileSystem> fileSystems;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated file system snapshot policy, which controls the frequency of snapshot creation and retention period of the taken snapshots.
     * 
     */
    private @Nullable String filesystemSnapshotPolicyId;
    private @Nullable List<GetFileSystemsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
     * 
     */
    private @Nullable String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningFS.htm).
     * 
     */
    private @Nullable String parentFileSystemId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningFS.htm).
     * 
     */
    private @Nullable String sourceSnapshotId;
    /**
     * @return The current state of the file system.
     * 
     */
    private @Nullable String state;

    private GetFileSystemsResult() {}
    /**
     * @return The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the file system.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My file system`
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of file_systems.
     * 
     */
    public List<GetFileSystemsFileSystem> fileSystems() {
        return this.fileSystems;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated file system snapshot policy, which controls the frequency of snapshot creation and retention period of the taken snapshots.
     * 
     */
    public Optional<String> filesystemSnapshotPolicyId() {
        return Optional.ofNullable(this.filesystemSnapshotPolicyId);
    }
    public List<GetFileSystemsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningFS.htm).
     * 
     */
    public Optional<String> parentFileSystemId() {
        return Optional.ofNullable(this.parentFileSystemId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningFS.htm).
     * 
     */
    public Optional<String> sourceSnapshotId() {
        return Optional.ofNullable(this.sourceSnapshotId);
    }
    /**
     * @return The current state of the file system.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFileSystemsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String compartmentId;
        private @Nullable String displayName;
        private List<GetFileSystemsFileSystem> fileSystems;
        private @Nullable String filesystemSnapshotPolicyId;
        private @Nullable List<GetFileSystemsFilter> filters;
        private @Nullable String id;
        private @Nullable String parentFileSystemId;
        private @Nullable String sourceSnapshotId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetFileSystemsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.fileSystems = defaults.fileSystems;
    	      this.filesystemSnapshotPolicyId = defaults.filesystemSnapshotPolicyId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.parentFileSystemId = defaults.parentFileSystemId;
    	      this.sourceSnapshotId = defaults.sourceSnapshotId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetFileSystemsResult", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetFileSystemsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder fileSystems(List<GetFileSystemsFileSystem> fileSystems) {
            if (fileSystems == null) {
              throw new MissingRequiredPropertyException("GetFileSystemsResult", "fileSystems");
            }
            this.fileSystems = fileSystems;
            return this;
        }
        public Builder fileSystems(GetFileSystemsFileSystem... fileSystems) {
            return fileSystems(List.of(fileSystems));
        }
        @CustomType.Setter
        public Builder filesystemSnapshotPolicyId(@Nullable String filesystemSnapshotPolicyId) {

            this.filesystemSnapshotPolicyId = filesystemSnapshotPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetFileSystemsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetFileSystemsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder parentFileSystemId(@Nullable String parentFileSystemId) {

            this.parentFileSystemId = parentFileSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder sourceSnapshotId(@Nullable String sourceSnapshotId) {

            this.sourceSnapshotId = sourceSnapshotId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetFileSystemsResult build() {
            final var _resultValue = new GetFileSystemsResult();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.fileSystems = fileSystems;
            _resultValue.filesystemSnapshotPolicyId = filesystemSnapshotPolicyId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.parentFileSystemId = parentFileSystemId;
            _resultValue.sourceSnapshotId = sourceSnapshotId;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
