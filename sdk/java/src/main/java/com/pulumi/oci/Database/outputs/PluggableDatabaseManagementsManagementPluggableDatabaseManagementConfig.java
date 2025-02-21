// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfig {
    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private Boolean enablePluggabledatabasemanagement;
    /**
     * @return The status of the Pluggable Database Management service.
     * 
     */
    private @Nullable String managementStatus;

    private PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfig() {}
    /**
     * @return (Updatable) A required field when set to `true` calls enable action and when set to `false` calls disable action.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Boolean enablePluggabledatabasemanagement() {
        return this.enablePluggabledatabasemanagement;
    }
    /**
     * @return The status of the Pluggable Database Management service.
     * 
     */
    public Optional<String> managementStatus() {
        return Optional.ofNullable(this.managementStatus);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean enablePluggabledatabasemanagement;
        private @Nullable String managementStatus;
        public Builder() {}
        public Builder(PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.enablePluggabledatabasemanagement = defaults.enablePluggabledatabasemanagement;
    	      this.managementStatus = defaults.managementStatus;
        }

        @CustomType.Setter
        public Builder enablePluggabledatabasemanagement(Boolean enablePluggabledatabasemanagement) {
            if (enablePluggabledatabasemanagement == null) {
              throw new MissingRequiredPropertyException("PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfig", "enablePluggabledatabasemanagement");
            }
            this.enablePluggabledatabasemanagement = enablePluggabledatabasemanagement;
            return this;
        }
        @CustomType.Setter
        public Builder managementStatus(@Nullable String managementStatus) {

            this.managementStatus = managementStatus;
            return this;
        }
        public PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfig build() {
            final var _resultValue = new PluggableDatabaseManagementsManagementPluggableDatabaseManagementConfig();
            _resultValue.enablePluggabledatabasemanagement = enablePluggabledatabasemanagement;
            _resultValue.managementStatus = managementStatus;
            return _resultValue;
        }
    }
}
