// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ContainerInstanceContainerVolumeMountArgs extends com.pulumi.resources.ResourceArgs {

    public static final ContainerInstanceContainerVolumeMountArgs Empty = new ContainerInstanceContainerVolumeMountArgs();

    /**
     * Whether the volume was mounted in read-only mode. By default, the volume is not read-only.
     * 
     */
    @Import(name="isReadOnly")
    private @Nullable Output<Boolean> isReadOnly;

    /**
     * @return Whether the volume was mounted in read-only mode. By default, the volume is not read-only.
     * 
     */
    public Optional<Output<Boolean>> isReadOnly() {
        return Optional.ofNullable(this.isReadOnly);
    }

    /**
     * The volume access path.
     * 
     */
    @Import(name="mountPath", required=true)
    private Output<String> mountPath;

    /**
     * @return The volume access path.
     * 
     */
    public Output<String> mountPath() {
        return this.mountPath;
    }

    /**
     * If there is more than one partition in the volume, reference this number of partitions. Here is an example: Number  Start   End     Size    File system  Name                  Flags 1      1049kB  106MB   105MB   fat16        EFI System Partition  boot, esp 2      106MB   1180MB  1074MB  xfs 3      1180MB  50.0GB  48.8GB                                     lvm
     * 
     */
    @Import(name="partition")
    private @Nullable Output<Integer> partition;

    /**
     * @return If there is more than one partition in the volume, reference this number of partitions. Here is an example: Number  Start   End     Size    File system  Name                  Flags 1      1049kB  106MB   105MB   fat16        EFI System Partition  boot, esp 2      106MB   1180MB  1074MB  xfs 3      1180MB  50.0GB  48.8GB                                     lvm
     * 
     */
    public Optional<Output<Integer>> partition() {
        return Optional.ofNullable(this.partition);
    }

    /**
     * A subpath inside the referenced volume.
     * 
     */
    @Import(name="subPath")
    private @Nullable Output<String> subPath;

    /**
     * @return A subpath inside the referenced volume.
     * 
     */
    public Optional<Output<String>> subPath() {
        return Optional.ofNullable(this.subPath);
    }

    /**
     * The name of the volume. Avoid entering confidential information.
     * 
     */
    @Import(name="volumeName", required=true)
    private Output<String> volumeName;

    /**
     * @return The name of the volume. Avoid entering confidential information.
     * 
     */
    public Output<String> volumeName() {
        return this.volumeName;
    }

    private ContainerInstanceContainerVolumeMountArgs() {}

    private ContainerInstanceContainerVolumeMountArgs(ContainerInstanceContainerVolumeMountArgs $) {
        this.isReadOnly = $.isReadOnly;
        this.mountPath = $.mountPath;
        this.partition = $.partition;
        this.subPath = $.subPath;
        this.volumeName = $.volumeName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ContainerInstanceContainerVolumeMountArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ContainerInstanceContainerVolumeMountArgs $;

        public Builder() {
            $ = new ContainerInstanceContainerVolumeMountArgs();
        }

        public Builder(ContainerInstanceContainerVolumeMountArgs defaults) {
            $ = new ContainerInstanceContainerVolumeMountArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isReadOnly Whether the volume was mounted in read-only mode. By default, the volume is not read-only.
         * 
         * @return builder
         * 
         */
        public Builder isReadOnly(@Nullable Output<Boolean> isReadOnly) {
            $.isReadOnly = isReadOnly;
            return this;
        }

        /**
         * @param isReadOnly Whether the volume was mounted in read-only mode. By default, the volume is not read-only.
         * 
         * @return builder
         * 
         */
        public Builder isReadOnly(Boolean isReadOnly) {
            return isReadOnly(Output.of(isReadOnly));
        }

        /**
         * @param mountPath The volume access path.
         * 
         * @return builder
         * 
         */
        public Builder mountPath(Output<String> mountPath) {
            $.mountPath = mountPath;
            return this;
        }

        /**
         * @param mountPath The volume access path.
         * 
         * @return builder
         * 
         */
        public Builder mountPath(String mountPath) {
            return mountPath(Output.of(mountPath));
        }

        /**
         * @param partition If there is more than one partition in the volume, reference this number of partitions. Here is an example: Number  Start   End     Size    File system  Name                  Flags 1      1049kB  106MB   105MB   fat16        EFI System Partition  boot, esp 2      106MB   1180MB  1074MB  xfs 3      1180MB  50.0GB  48.8GB                                     lvm
         * 
         * @return builder
         * 
         */
        public Builder partition(@Nullable Output<Integer> partition) {
            $.partition = partition;
            return this;
        }

        /**
         * @param partition If there is more than one partition in the volume, reference this number of partitions. Here is an example: Number  Start   End     Size    File system  Name                  Flags 1      1049kB  106MB   105MB   fat16        EFI System Partition  boot, esp 2      106MB   1180MB  1074MB  xfs 3      1180MB  50.0GB  48.8GB                                     lvm
         * 
         * @return builder
         * 
         */
        public Builder partition(Integer partition) {
            return partition(Output.of(partition));
        }

        /**
         * @param subPath A subpath inside the referenced volume.
         * 
         * @return builder
         * 
         */
        public Builder subPath(@Nullable Output<String> subPath) {
            $.subPath = subPath;
            return this;
        }

        /**
         * @param subPath A subpath inside the referenced volume.
         * 
         * @return builder
         * 
         */
        public Builder subPath(String subPath) {
            return subPath(Output.of(subPath));
        }

        /**
         * @param volumeName The name of the volume. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder volumeName(Output<String> volumeName) {
            $.volumeName = volumeName;
            return this;
        }

        /**
         * @param volumeName The name of the volume. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder volumeName(String volumeName) {
            return volumeName(Output.of(volumeName));
        }

        public ContainerInstanceContainerVolumeMountArgs build() {
            if ($.mountPath == null) {
                throw new MissingRequiredPropertyException("ContainerInstanceContainerVolumeMountArgs", "mountPath");
            }
            if ($.volumeName == null) {
                throw new MissingRequiredPropertyException("ContainerInstanceContainerVolumeMountArgs", "volumeName");
            }
            return $;
        }
    }

}
