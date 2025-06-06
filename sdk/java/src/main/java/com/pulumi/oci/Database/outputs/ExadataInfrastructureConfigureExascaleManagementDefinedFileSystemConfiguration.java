// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExadataInfrastructureConfigureExascaleManagementDefinedFileSystemConfiguration {
    /**
     * @return If true, the file system is used to create a backup prior to Exadata VM OS update.
     * 
     */
    private @Nullable Boolean isBackupPartition;
    /**
     * @return If true, the file system resize is allowed for the Exadata Infrastructure cluster. If false, the file system resize is not allowed.
     * 
     */
    private @Nullable Boolean isResizable;
    /**
     * @return The minimum size of file system.
     * 
     */
    private @Nullable Integer minSizeGb;
    /**
     * @return The mount point of file system.
     * 
     */
    private @Nullable String mountPoint;

    private ExadataInfrastructureConfigureExascaleManagementDefinedFileSystemConfiguration() {}
    /**
     * @return If true, the file system is used to create a backup prior to Exadata VM OS update.
     * 
     */
    public Optional<Boolean> isBackupPartition() {
        return Optional.ofNullable(this.isBackupPartition);
    }
    /**
     * @return If true, the file system resize is allowed for the Exadata Infrastructure cluster. If false, the file system resize is not allowed.
     * 
     */
    public Optional<Boolean> isResizable() {
        return Optional.ofNullable(this.isResizable);
    }
    /**
     * @return The minimum size of file system.
     * 
     */
    public Optional<Integer> minSizeGb() {
        return Optional.ofNullable(this.minSizeGb);
    }
    /**
     * @return The mount point of file system.
     * 
     */
    public Optional<String> mountPoint() {
        return Optional.ofNullable(this.mountPoint);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExadataInfrastructureConfigureExascaleManagementDefinedFileSystemConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isBackupPartition;
        private @Nullable Boolean isResizable;
        private @Nullable Integer minSizeGb;
        private @Nullable String mountPoint;
        public Builder() {}
        public Builder(ExadataInfrastructureConfigureExascaleManagementDefinedFileSystemConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isBackupPartition = defaults.isBackupPartition;
    	      this.isResizable = defaults.isResizable;
    	      this.minSizeGb = defaults.minSizeGb;
    	      this.mountPoint = defaults.mountPoint;
        }

        @CustomType.Setter
        public Builder isBackupPartition(@Nullable Boolean isBackupPartition) {

            this.isBackupPartition = isBackupPartition;
            return this;
        }
        @CustomType.Setter
        public Builder isResizable(@Nullable Boolean isResizable) {

            this.isResizable = isResizable;
            return this;
        }
        @CustomType.Setter
        public Builder minSizeGb(@Nullable Integer minSizeGb) {

            this.minSizeGb = minSizeGb;
            return this;
        }
        @CustomType.Setter
        public Builder mountPoint(@Nullable String mountPoint) {

            this.mountPoint = mountPoint;
            return this;
        }
        public ExadataInfrastructureConfigureExascaleManagementDefinedFileSystemConfiguration build() {
            final var _resultValue = new ExadataInfrastructureConfigureExascaleManagementDefinedFileSystemConfiguration();
            _resultValue.isBackupPartition = isBackupPartition;
            _resultValue.isResizable = isResizable;
            _resultValue.minSizeGb = minSizeGb;
            _resultValue.mountPoint = mountPoint;
            return _resultValue;
        }
    }
}
