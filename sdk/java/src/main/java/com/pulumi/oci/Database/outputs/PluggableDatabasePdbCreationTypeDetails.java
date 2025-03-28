// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetails;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PluggableDatabasePdbCreationTypeDetails {
    /**
     * @return The Pluggable Database creation type.
     * 
     */
    private String creationType;
    /**
     * @return The DB link user password.
     * 
     */
    private @Nullable String dblinkUserPassword;
    /**
     * @return The name of the DB link user.
     * 
     */
    private @Nullable String dblinkUsername;
    /**
     * @return True if Pluggable Database needs to be thin cloned and false if Pluggable Database needs to be thick cloned.
     * 
     */
    private @Nullable Boolean isThinClone;
    /**
     * @return Parameters for creating Pluggable Database Refreshable Clone. **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
     * 
     */
    private @Nullable PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetails refreshableCloneDetails;
    /**
     * @return The DB system administrator password of the source Container Database.
     * 
     */
    private @Nullable String sourceContainerDatabaseAdminPassword;
    /**
     * @return The OCID of the Source Pluggable Database.
     * 
     */
    private String sourcePluggableDatabaseId;

    private PluggableDatabasePdbCreationTypeDetails() {}
    /**
     * @return The Pluggable Database creation type.
     * 
     */
    public String creationType() {
        return this.creationType;
    }
    /**
     * @return The DB link user password.
     * 
     */
    public Optional<String> dblinkUserPassword() {
        return Optional.ofNullable(this.dblinkUserPassword);
    }
    /**
     * @return The name of the DB link user.
     * 
     */
    public Optional<String> dblinkUsername() {
        return Optional.ofNullable(this.dblinkUsername);
    }
    /**
     * @return True if Pluggable Database needs to be thin cloned and false if Pluggable Database needs to be thick cloned.
     * 
     */
    public Optional<Boolean> isThinClone() {
        return Optional.ofNullable(this.isThinClone);
    }
    /**
     * @return Parameters for creating Pluggable Database Refreshable Clone. **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
     * 
     */
    public Optional<PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetails> refreshableCloneDetails() {
        return Optional.ofNullable(this.refreshableCloneDetails);
    }
    /**
     * @return The DB system administrator password of the source Container Database.
     * 
     */
    public Optional<String> sourceContainerDatabaseAdminPassword() {
        return Optional.ofNullable(this.sourceContainerDatabaseAdminPassword);
    }
    /**
     * @return The OCID of the Source Pluggable Database.
     * 
     */
    public String sourcePluggableDatabaseId() {
        return this.sourcePluggableDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PluggableDatabasePdbCreationTypeDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String creationType;
        private @Nullable String dblinkUserPassword;
        private @Nullable String dblinkUsername;
        private @Nullable Boolean isThinClone;
        private @Nullable PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetails refreshableCloneDetails;
        private @Nullable String sourceContainerDatabaseAdminPassword;
        private String sourcePluggableDatabaseId;
        public Builder() {}
        public Builder(PluggableDatabasePdbCreationTypeDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.creationType = defaults.creationType;
    	      this.dblinkUserPassword = defaults.dblinkUserPassword;
    	      this.dblinkUsername = defaults.dblinkUsername;
    	      this.isThinClone = defaults.isThinClone;
    	      this.refreshableCloneDetails = defaults.refreshableCloneDetails;
    	      this.sourceContainerDatabaseAdminPassword = defaults.sourceContainerDatabaseAdminPassword;
    	      this.sourcePluggableDatabaseId = defaults.sourcePluggableDatabaseId;
        }

        @CustomType.Setter
        public Builder creationType(String creationType) {
            if (creationType == null) {
              throw new MissingRequiredPropertyException("PluggableDatabasePdbCreationTypeDetails", "creationType");
            }
            this.creationType = creationType;
            return this;
        }
        @CustomType.Setter
        public Builder dblinkUserPassword(@Nullable String dblinkUserPassword) {

            this.dblinkUserPassword = dblinkUserPassword;
            return this;
        }
        @CustomType.Setter
        public Builder dblinkUsername(@Nullable String dblinkUsername) {

            this.dblinkUsername = dblinkUsername;
            return this;
        }
        @CustomType.Setter
        public Builder isThinClone(@Nullable Boolean isThinClone) {

            this.isThinClone = isThinClone;
            return this;
        }
        @CustomType.Setter
        public Builder refreshableCloneDetails(@Nullable PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetails refreshableCloneDetails) {

            this.refreshableCloneDetails = refreshableCloneDetails;
            return this;
        }
        @CustomType.Setter
        public Builder sourceContainerDatabaseAdminPassword(@Nullable String sourceContainerDatabaseAdminPassword) {

            this.sourceContainerDatabaseAdminPassword = sourceContainerDatabaseAdminPassword;
            return this;
        }
        @CustomType.Setter
        public Builder sourcePluggableDatabaseId(String sourcePluggableDatabaseId) {
            if (sourcePluggableDatabaseId == null) {
              throw new MissingRequiredPropertyException("PluggableDatabasePdbCreationTypeDetails", "sourcePluggableDatabaseId");
            }
            this.sourcePluggableDatabaseId = sourcePluggableDatabaseId;
            return this;
        }
        public PluggableDatabasePdbCreationTypeDetails build() {
            final var _resultValue = new PluggableDatabasePdbCreationTypeDetails();
            _resultValue.creationType = creationType;
            _resultValue.dblinkUserPassword = dblinkUserPassword;
            _resultValue.dblinkUsername = dblinkUsername;
            _resultValue.isThinClone = isThinClone;
            _resultValue.refreshableCloneDetails = refreshableCloneDetails;
            _resultValue.sourceContainerDatabaseAdminPassword = sourceContainerDatabaseAdminPassword;
            _resultValue.sourcePluggableDatabaseId = sourcePluggableDatabaseId;
            return _resultValue;
        }
    }
}
