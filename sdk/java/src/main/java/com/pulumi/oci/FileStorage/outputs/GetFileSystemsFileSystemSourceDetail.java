// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FileStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFileSystemsFileSystemSourceDetail {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     * 
     */
    private String parentFileSystemId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     * 
     */
    private String sourceSnapshotId;

    private GetFileSystemsFileSystemSourceDetail() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     * 
     */
    public String parentFileSystemId() {
        return this.parentFileSystemId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
     * 
     */
    public String sourceSnapshotId() {
        return this.sourceSnapshotId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFileSystemsFileSystemSourceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String parentFileSystemId;
        private String sourceSnapshotId;
        public Builder() {}
        public Builder(GetFileSystemsFileSystemSourceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.parentFileSystemId = defaults.parentFileSystemId;
    	      this.sourceSnapshotId = defaults.sourceSnapshotId;
        }

        @CustomType.Setter
        public Builder parentFileSystemId(String parentFileSystemId) {
            this.parentFileSystemId = Objects.requireNonNull(parentFileSystemId);
            return this;
        }
        @CustomType.Setter
        public Builder sourceSnapshotId(String sourceSnapshotId) {
            this.sourceSnapshotId = Objects.requireNonNull(sourceSnapshotId);
            return this;
        }
        public GetFileSystemsFileSystemSourceDetail build() {
            final var o = new GetFileSystemsFileSystemSourceDetail();
            o.parentFileSystemId = parentFileSystemId;
            o.sourceSnapshotId = sourceSnapshotId;
            return o;
        }
    }
}