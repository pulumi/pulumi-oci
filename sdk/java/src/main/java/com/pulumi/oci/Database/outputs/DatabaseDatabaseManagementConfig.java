// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DatabaseDatabaseManagementConfig {
    /**
     * @return The status of the Database Management service.
     * 
     */
    private final @Nullable String managementStatus;
    /**
     * @return The Database Management type.
     * 
     */
    private final @Nullable String managementType;

    @CustomType.Constructor
    private DatabaseDatabaseManagementConfig(
        @CustomType.Parameter("managementStatus") @Nullable String managementStatus,
        @CustomType.Parameter("managementType") @Nullable String managementType) {
        this.managementStatus = managementStatus;
        this.managementType = managementType;
    }

    /**
     * @return The status of the Database Management service.
     * 
     */
    public Optional<String> managementStatus() {
        return Optional.ofNullable(this.managementStatus);
    }
    /**
     * @return The Database Management type.
     * 
     */
    public Optional<String> managementType() {
        return Optional.ofNullable(this.managementType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DatabaseDatabaseManagementConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String managementStatus;
        private @Nullable String managementType;

        public Builder() {
    	      // Empty
        }

        public Builder(DatabaseDatabaseManagementConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.managementStatus = defaults.managementStatus;
    	      this.managementType = defaults.managementType;
        }

        public Builder managementStatus(@Nullable String managementStatus) {
            this.managementStatus = managementStatus;
            return this;
        }
        public Builder managementType(@Nullable String managementType) {
            this.managementType = managementType;
            return this;
        }        public DatabaseDatabaseManagementConfig build() {
            return new DatabaseDatabaseManagementConfig(managementStatus, managementType);
        }
    }
}
