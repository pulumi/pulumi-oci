// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DatabaseUpgradeDatabaseUpgradeSourceDetails {
    /**
     * @return The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image to be used to upgrade a database.
     * 
     */
    private @Nullable String databaseSoftwareImageId;
    /**
     * @return A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
     * 
     */
    private @Nullable String dbVersion;
    /**
     * @return Additional upgrade options supported by DBUA(Database Upgrade Assistant). Example: &#34;-upgradeTimezone false -keepEvents&#34;
     * 
     */
    private @Nullable String options;
    /**
     * @return The source of the Oracle Database software to be used for the upgrade.
     * * Use `DB_VERSION` to specify a generally-available Oracle Database software version to upgrade the database.
     * * Use `DB_SOFTWARE_IMAGE` to specify a [database software image](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/databasesoftwareimage.htm) to upgrade the database.
     * 
     */
    private @Nullable String source;

    private DatabaseUpgradeDatabaseUpgradeSourceDetails() {}
    /**
     * @return The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image to be used to upgrade a database.
     * 
     */
    public Optional<String> databaseSoftwareImageId() {
        return Optional.ofNullable(this.databaseSoftwareImageId);
    }
    /**
     * @return A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
     * 
     */
    public Optional<String> dbVersion() {
        return Optional.ofNullable(this.dbVersion);
    }
    /**
     * @return Additional upgrade options supported by DBUA(Database Upgrade Assistant). Example: &#34;-upgradeTimezone false -keepEvents&#34;
     * 
     */
    public Optional<String> options() {
        return Optional.ofNullable(this.options);
    }
    /**
     * @return The source of the Oracle Database software to be used for the upgrade.
     * * Use `DB_VERSION` to specify a generally-available Oracle Database software version to upgrade the database.
     * * Use `DB_SOFTWARE_IMAGE` to specify a [database software image](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/databasesoftwareimage.htm) to upgrade the database.
     * 
     */
    public Optional<String> source() {
        return Optional.ofNullable(this.source);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DatabaseUpgradeDatabaseUpgradeSourceDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String databaseSoftwareImageId;
        private @Nullable String dbVersion;
        private @Nullable String options;
        private @Nullable String source;
        public Builder() {}
        public Builder(DatabaseUpgradeDatabaseUpgradeSourceDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.databaseSoftwareImageId = defaults.databaseSoftwareImageId;
    	      this.dbVersion = defaults.dbVersion;
    	      this.options = defaults.options;
    	      this.source = defaults.source;
        }

        @CustomType.Setter
        public Builder databaseSoftwareImageId(@Nullable String databaseSoftwareImageId) {
            this.databaseSoftwareImageId = databaseSoftwareImageId;
            return this;
        }
        @CustomType.Setter
        public Builder dbVersion(@Nullable String dbVersion) {
            this.dbVersion = dbVersion;
            return this;
        }
        @CustomType.Setter
        public Builder options(@Nullable String options) {
            this.options = options;
            return this;
        }
        @CustomType.Setter
        public Builder source(@Nullable String source) {
            this.source = source;
            return this;
        }
        public DatabaseUpgradeDatabaseUpgradeSourceDetails build() {
            final var o = new DatabaseUpgradeDatabaseUpgradeSourceDetails();
            o.databaseSoftwareImageId = databaseSoftwareImageId;
            o.dbVersion = dbVersion;
            o.options = options;
            o.source = source;
            return o;
        }
    }
}