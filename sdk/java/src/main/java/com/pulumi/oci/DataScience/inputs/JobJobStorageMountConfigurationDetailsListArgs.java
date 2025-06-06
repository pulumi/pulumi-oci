// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class JobJobStorageMountConfigurationDetailsListArgs extends com.pulumi.resources.ResourceArgs {

    public static final JobJobStorageMountConfigurationDetailsListArgs Empty = new JobJobStorageMountConfigurationDetailsListArgs();

    /**
     * (Updatable) The object storage bucket
     * 
     */
    @Import(name="bucket")
    private @Nullable Output<String> bucket;

    /**
     * @return (Updatable) The object storage bucket
     * 
     */
    public Optional<Output<String>> bucket() {
        return Optional.ofNullable(this.bucket);
    }

    /**
     * (Updatable) The local directory name to be mounted
     * 
     */
    @Import(name="destinationDirectoryName", required=true)
    private Output<String> destinationDirectoryName;

    /**
     * @return (Updatable) The local directory name to be mounted
     * 
     */
    public Output<String> destinationDirectoryName() {
        return this.destinationDirectoryName;
    }

    /**
     * (Updatable) The local path of the mounted directory, excluding directory name.
     * 
     */
    @Import(name="destinationPath")
    private @Nullable Output<String> destinationPath;

    /**
     * @return (Updatable) The local path of the mounted directory, excluding directory name.
     * 
     */
    public Optional<Output<String>> destinationPath() {
        return Optional.ofNullable(this.destinationPath);
    }

    /**
     * (Updatable) OCID of the export
     * 
     */
    @Import(name="exportId")
    private @Nullable Output<String> exportId;

    /**
     * @return (Updatable) OCID of the export
     * 
     */
    public Optional<Output<String>> exportId() {
        return Optional.ofNullable(this.exportId);
    }

    /**
     * (Updatable) OCID of the mount target
     * 
     */
    @Import(name="mountTargetId")
    private @Nullable Output<String> mountTargetId;

    /**
     * @return (Updatable) OCID of the mount target
     * 
     */
    public Optional<Output<String>> mountTargetId() {
        return Optional.ofNullable(this.mountTargetId);
    }

    /**
     * (Updatable) The object storage namespace
     * 
     */
    @Import(name="namespace")
    private @Nullable Output<String> namespace;

    /**
     * @return (Updatable) The object storage namespace
     * 
     */
    public Optional<Output<String>> namespace() {
        return Optional.ofNullable(this.namespace);
    }

    /**
     * (Updatable) Prefix in the bucket to mount
     * 
     */
    @Import(name="prefix")
    private @Nullable Output<String> prefix;

    /**
     * @return (Updatable) Prefix in the bucket to mount
     * 
     */
    public Optional<Output<String>> prefix() {
        return Optional.ofNullable(this.prefix);
    }

    /**
     * (Updatable) The type of storage.
     * 
     */
    @Import(name="storageType", required=true)
    private Output<String> storageType;

    /**
     * @return (Updatable) The type of storage.
     * 
     */
    public Output<String> storageType() {
        return this.storageType;
    }

    private JobJobStorageMountConfigurationDetailsListArgs() {}

    private JobJobStorageMountConfigurationDetailsListArgs(JobJobStorageMountConfigurationDetailsListArgs $) {
        this.bucket = $.bucket;
        this.destinationDirectoryName = $.destinationDirectoryName;
        this.destinationPath = $.destinationPath;
        this.exportId = $.exportId;
        this.mountTargetId = $.mountTargetId;
        this.namespace = $.namespace;
        this.prefix = $.prefix;
        this.storageType = $.storageType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(JobJobStorageMountConfigurationDetailsListArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private JobJobStorageMountConfigurationDetailsListArgs $;

        public Builder() {
            $ = new JobJobStorageMountConfigurationDetailsListArgs();
        }

        public Builder(JobJobStorageMountConfigurationDetailsListArgs defaults) {
            $ = new JobJobStorageMountConfigurationDetailsListArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket (Updatable) The object storage bucket
         * 
         * @return builder
         * 
         */
        public Builder bucket(@Nullable Output<String> bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param bucket (Updatable) The object storage bucket
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            return bucket(Output.of(bucket));
        }

        /**
         * @param destinationDirectoryName (Updatable) The local directory name to be mounted
         * 
         * @return builder
         * 
         */
        public Builder destinationDirectoryName(Output<String> destinationDirectoryName) {
            $.destinationDirectoryName = destinationDirectoryName;
            return this;
        }

        /**
         * @param destinationDirectoryName (Updatable) The local directory name to be mounted
         * 
         * @return builder
         * 
         */
        public Builder destinationDirectoryName(String destinationDirectoryName) {
            return destinationDirectoryName(Output.of(destinationDirectoryName));
        }

        /**
         * @param destinationPath (Updatable) The local path of the mounted directory, excluding directory name.
         * 
         * @return builder
         * 
         */
        public Builder destinationPath(@Nullable Output<String> destinationPath) {
            $.destinationPath = destinationPath;
            return this;
        }

        /**
         * @param destinationPath (Updatable) The local path of the mounted directory, excluding directory name.
         * 
         * @return builder
         * 
         */
        public Builder destinationPath(String destinationPath) {
            return destinationPath(Output.of(destinationPath));
        }

        /**
         * @param exportId (Updatable) OCID of the export
         * 
         * @return builder
         * 
         */
        public Builder exportId(@Nullable Output<String> exportId) {
            $.exportId = exportId;
            return this;
        }

        /**
         * @param exportId (Updatable) OCID of the export
         * 
         * @return builder
         * 
         */
        public Builder exportId(String exportId) {
            return exportId(Output.of(exportId));
        }

        /**
         * @param mountTargetId (Updatable) OCID of the mount target
         * 
         * @return builder
         * 
         */
        public Builder mountTargetId(@Nullable Output<String> mountTargetId) {
            $.mountTargetId = mountTargetId;
            return this;
        }

        /**
         * @param mountTargetId (Updatable) OCID of the mount target
         * 
         * @return builder
         * 
         */
        public Builder mountTargetId(String mountTargetId) {
            return mountTargetId(Output.of(mountTargetId));
        }

        /**
         * @param namespace (Updatable) The object storage namespace
         * 
         * @return builder
         * 
         */
        public Builder namespace(@Nullable Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace (Updatable) The object storage namespace
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param prefix (Updatable) Prefix in the bucket to mount
         * 
         * @return builder
         * 
         */
        public Builder prefix(@Nullable Output<String> prefix) {
            $.prefix = prefix;
            return this;
        }

        /**
         * @param prefix (Updatable) Prefix in the bucket to mount
         * 
         * @return builder
         * 
         */
        public Builder prefix(String prefix) {
            return prefix(Output.of(prefix));
        }

        /**
         * @param storageType (Updatable) The type of storage.
         * 
         * @return builder
         * 
         */
        public Builder storageType(Output<String> storageType) {
            $.storageType = storageType;
            return this;
        }

        /**
         * @param storageType (Updatable) The type of storage.
         * 
         * @return builder
         * 
         */
        public Builder storageType(String storageType) {
            return storageType(Output.of(storageType));
        }

        public JobJobStorageMountConfigurationDetailsListArgs build() {
            if ($.destinationDirectoryName == null) {
                throw new MissingRequiredPropertyException("JobJobStorageMountConfigurationDetailsListArgs", "destinationDirectoryName");
            }
            if ($.storageType == null) {
                throw new MissingRequiredPropertyException("JobJobStorageMountConfigurationDetailsListArgs", "storageType");
            }
            return $;
        }
    }

}
