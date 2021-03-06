// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetDatabaseDatabaseDbBackupConfigBackupDestinationDetail;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDatabaseDatabaseDbBackupConfig {
    /**
     * @return If set to true, configures automatic backups. If you previously used RMAN or dbcli to configure backups and then you switch to using the Console or the API for backups, a new backup configuration is created and associated with your database. This means that you can no longer rely on your previously configured unmanaged backups to work.
     * 
     */
    private final Boolean autoBackupEnabled;
    /**
     * @return Time window selected for initiating automatic backup for the database system. There are twelve available two-hour time windows. If no option is selected, a start time between 12:00 AM to 7:00 AM in the region of the database is automatically chosen. For example, if the user selects SLOT_TWO from the enum list, the automatic backup job will start in between 2:00 AM (inclusive) to 4:00 AM (exclusive).  Example: `SLOT_TWO`
     * 
     */
    private final String autoBackupWindow;
    /**
     * @return Backup destination details.
     * 
     */
    private final List<GetDatabaseDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails;
    /**
     * @return Number of days between the current and the earliest point of recoverability covered by automatic backups. This value applies to automatic backups only. After a new automatic backup has been created, Oracle removes old automatic backups that are created before the window. When the value is updated, it is applied to all existing automatic backups.
     * 
     */
    private final Integer recoveryWindowInDays;

    @CustomType.Constructor
    private GetDatabaseDatabaseDbBackupConfig(
        @CustomType.Parameter("autoBackupEnabled") Boolean autoBackupEnabled,
        @CustomType.Parameter("autoBackupWindow") String autoBackupWindow,
        @CustomType.Parameter("backupDestinationDetails") List<GetDatabaseDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails,
        @CustomType.Parameter("recoveryWindowInDays") Integer recoveryWindowInDays) {
        this.autoBackupEnabled = autoBackupEnabled;
        this.autoBackupWindow = autoBackupWindow;
        this.backupDestinationDetails = backupDestinationDetails;
        this.recoveryWindowInDays = recoveryWindowInDays;
    }

    /**
     * @return If set to true, configures automatic backups. If you previously used RMAN or dbcli to configure backups and then you switch to using the Console or the API for backups, a new backup configuration is created and associated with your database. This means that you can no longer rely on your previously configured unmanaged backups to work.
     * 
     */
    public Boolean autoBackupEnabled() {
        return this.autoBackupEnabled;
    }
    /**
     * @return Time window selected for initiating automatic backup for the database system. There are twelve available two-hour time windows. If no option is selected, a start time between 12:00 AM to 7:00 AM in the region of the database is automatically chosen. For example, if the user selects SLOT_TWO from the enum list, the automatic backup job will start in between 2:00 AM (inclusive) to 4:00 AM (exclusive).  Example: `SLOT_TWO`
     * 
     */
    public String autoBackupWindow() {
        return this.autoBackupWindow;
    }
    /**
     * @return Backup destination details.
     * 
     */
    public List<GetDatabaseDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails() {
        return this.backupDestinationDetails;
    }
    /**
     * @return Number of days between the current and the earliest point of recoverability covered by automatic backups. This value applies to automatic backups only. After a new automatic backup has been created, Oracle removes old automatic backups that are created before the window. When the value is updated, it is applied to all existing automatic backups.
     * 
     */
    public Integer recoveryWindowInDays() {
        return this.recoveryWindowInDays;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseDatabaseDbBackupConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Boolean autoBackupEnabled;
        private String autoBackupWindow;
        private List<GetDatabaseDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails;
        private Integer recoveryWindowInDays;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDatabaseDatabaseDbBackupConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autoBackupEnabled = defaults.autoBackupEnabled;
    	      this.autoBackupWindow = defaults.autoBackupWindow;
    	      this.backupDestinationDetails = defaults.backupDestinationDetails;
    	      this.recoveryWindowInDays = defaults.recoveryWindowInDays;
        }

        public Builder autoBackupEnabled(Boolean autoBackupEnabled) {
            this.autoBackupEnabled = Objects.requireNonNull(autoBackupEnabled);
            return this;
        }
        public Builder autoBackupWindow(String autoBackupWindow) {
            this.autoBackupWindow = Objects.requireNonNull(autoBackupWindow);
            return this;
        }
        public Builder backupDestinationDetails(List<GetDatabaseDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails) {
            this.backupDestinationDetails = Objects.requireNonNull(backupDestinationDetails);
            return this;
        }
        public Builder backupDestinationDetails(GetDatabaseDatabaseDbBackupConfigBackupDestinationDetail... backupDestinationDetails) {
            return backupDestinationDetails(List.of(backupDestinationDetails));
        }
        public Builder recoveryWindowInDays(Integer recoveryWindowInDays) {
            this.recoveryWindowInDays = Objects.requireNonNull(recoveryWindowInDays);
            return this;
        }        public GetDatabaseDatabaseDbBackupConfig build() {
            return new GetDatabaseDatabaseDbBackupConfig(autoBackupEnabled, autoBackupWindow, backupDestinationDetails, recoveryWindowInDays);
        }
    }
}
