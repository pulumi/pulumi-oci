// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry {
    /**
     * @return The database upgrade action.
     * 
     */
    private String action;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database upgrade history.
     * 
     */
    private String id;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return Additional upgrade options supported by DBUA(Database Upgrade Assistant). Example: &#34;-upgradeTimezone false -keepEvents&#34;
     * 
     */
    private String options;
    /**
     * @return The source of the Oracle Database software to be used for the upgrade.
     * * Use `DB_VERSION` to specify a generally-available Oracle Database software version to upgrade the database.
     * * Use `DB_SOFTWARE_IMAGE` to specify a [database software image](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/databasesoftwareimage.htm) to upgrade the database.
     * 
     */
    private String source;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
     * 
     */
    private String sourceDbHomeId;
    /**
     * @return A filter to return only upgradeHistoryEntries that match the given lifecycle state exactly.
     * 
     */
    private String state;
    /**
     * @return the database software image used for upgrading database.
     * 
     */
    private String targetDatabaseSoftwareImageId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
     * 
     */
    private String targetDbHomeId;
    /**
     * @return A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
     * 
     */
    private String targetDbVersion;
    /**
     * @return The date and time when the database upgrade ended.
     * 
     */
    private String timeEnded;
    /**
     * @return The date and time when the database upgrade started.
     * 
     */
    private String timeStarted;

    private GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry() {}
    /**
     * @return The database upgrade action.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database upgrade history.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return Additional upgrade options supported by DBUA(Database Upgrade Assistant). Example: &#34;-upgradeTimezone false -keepEvents&#34;
     * 
     */
    public String options() {
        return this.options;
    }
    /**
     * @return The source of the Oracle Database software to be used for the upgrade.
     * * Use `DB_VERSION` to specify a generally-available Oracle Database software version to upgrade the database.
     * * Use `DB_SOFTWARE_IMAGE` to specify a [database software image](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/databasesoftwareimage.htm) to upgrade the database.
     * 
     */
    public String source() {
        return this.source;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
     * 
     */
    public String sourceDbHomeId() {
        return this.sourceDbHomeId;
    }
    /**
     * @return A filter to return only upgradeHistoryEntries that match the given lifecycle state exactly.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return the database software image used for upgrading database.
     * 
     */
    public String targetDatabaseSoftwareImageId() {
        return this.targetDatabaseSoftwareImageId;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
     * 
     */
    public String targetDbHomeId() {
        return this.targetDbHomeId;
    }
    /**
     * @return A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
     * 
     */
    public String targetDbVersion() {
        return this.targetDbVersion;
    }
    /**
     * @return The date and time when the database upgrade ended.
     * 
     */
    public String timeEnded() {
        return this.timeEnded;
    }
    /**
     * @return The date and time when the database upgrade started.
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private String id;
        private String lifecycleDetails;
        private String options;
        private String source;
        private String sourceDbHomeId;
        private String state;
        private String targetDatabaseSoftwareImageId;
        private String targetDbHomeId;
        private String targetDbVersion;
        private String timeEnded;
        private String timeStarted;
        public Builder() {}
        public Builder(GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.options = defaults.options;
    	      this.source = defaults.source;
    	      this.sourceDbHomeId = defaults.sourceDbHomeId;
    	      this.state = defaults.state;
    	      this.targetDatabaseSoftwareImageId = defaults.targetDatabaseSoftwareImageId;
    	      this.targetDbHomeId = defaults.targetDbHomeId;
    	      this.targetDbVersion = defaults.targetDbVersion;
    	      this.timeEnded = defaults.timeEnded;
    	      this.timeStarted = defaults.timeStarted;
        }

        @CustomType.Setter
        public Builder action(String action) {
            this.action = Objects.requireNonNull(action);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder options(String options) {
            this.options = Objects.requireNonNull(options);
            return this;
        }
        @CustomType.Setter
        public Builder source(String source) {
            this.source = Objects.requireNonNull(source);
            return this;
        }
        @CustomType.Setter
        public Builder sourceDbHomeId(String sourceDbHomeId) {
            this.sourceDbHomeId = Objects.requireNonNull(sourceDbHomeId);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder targetDatabaseSoftwareImageId(String targetDatabaseSoftwareImageId) {
            this.targetDatabaseSoftwareImageId = Objects.requireNonNull(targetDatabaseSoftwareImageId);
            return this;
        }
        @CustomType.Setter
        public Builder targetDbHomeId(String targetDbHomeId) {
            this.targetDbHomeId = Objects.requireNonNull(targetDbHomeId);
            return this;
        }
        @CustomType.Setter
        public Builder targetDbVersion(String targetDbVersion) {
            this.targetDbVersion = Objects.requireNonNull(targetDbVersion);
            return this;
        }
        @CustomType.Setter
        public Builder timeEnded(String timeEnded) {
            this.timeEnded = Objects.requireNonNull(timeEnded);
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(String timeStarted) {
            this.timeStarted = Objects.requireNonNull(timeStarted);
            return this;
        }
        public GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry build() {
            final var o = new GetDatabaseUpgradeHistoryEntriesDatabaseUpgradeHistoryEntry();
            o.action = action;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.options = options;
            o.source = source;
            o.sourceDbHomeId = sourceDbHomeId;
            o.state = state;
            o.targetDatabaseSoftwareImageId = targetDatabaseSoftwareImageId;
            o.targetDbHomeId = targetDbHomeId;
            o.targetDbVersion = targetDbVersion;
            o.timeEnded = timeEnded;
            o.timeStarted = timeStarted;
            return o;
        }
    }
}