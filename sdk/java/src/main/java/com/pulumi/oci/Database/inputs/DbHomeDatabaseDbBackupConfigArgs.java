// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Database.inputs.DbHomeDatabaseDbBackupConfigBackupDestinationDetailArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DbHomeDatabaseDbBackupConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final DbHomeDatabaseDbBackupConfigArgs Empty = new DbHomeDatabaseDbBackupConfigArgs();

    /**
     * (Updatable) If set to true, configures automatic backups. If you previously used RMAN or dbcli to configure backups and then you switch to using the Console or the API for backups, a new backup configuration is created and associated with your database. This means that you can no longer rely on your previously configured unmanaged backups to work.
     * 
     */
    @Import(name="autoBackupEnabled")
    private @Nullable Output<Boolean> autoBackupEnabled;

    /**
     * @return (Updatable) If set to true, configures automatic backups. If you previously used RMAN or dbcli to configure backups and then you switch to using the Console or the API for backups, a new backup configuration is created and associated with your database. This means that you can no longer rely on your previously configured unmanaged backups to work.
     * 
     */
    public Optional<Output<Boolean>> autoBackupEnabled() {
        return Optional.ofNullable(this.autoBackupEnabled);
    }

    /**
     * (Updatable) Time window selected for initiating automatic backup for the database system. There are twelve available two-hour time windows. If no option is selected, a start time between 12:00 AM to 7:00 AM in the region of the database is automatically chosen. For example, if the user selects SLOT_TWO from the enum list, the automatic backup job will start in between 2:00 AM (inclusive) to 4:00 AM (exclusive).  Example: `SLOT_TWO`
     * 
     */
    @Import(name="autoBackupWindow")
    private @Nullable Output<String> autoBackupWindow;

    /**
     * @return (Updatable) Time window selected for initiating automatic backup for the database system. There are twelve available two-hour time windows. If no option is selected, a start time between 12:00 AM to 7:00 AM in the region of the database is automatically chosen. For example, if the user selects SLOT_TWO from the enum list, the automatic backup job will start in between 2:00 AM (inclusive) to 4:00 AM (exclusive).  Example: `SLOT_TWO`
     * 
     */
    public Optional<Output<String>> autoBackupWindow() {
        return Optional.ofNullable(this.autoBackupWindow);
    }

    /**
     * Backup destination details.
     * 
     */
    @Import(name="backupDestinationDetails")
    private @Nullable Output<List<DbHomeDatabaseDbBackupConfigBackupDestinationDetailArgs>> backupDestinationDetails;

    /**
     * @return Backup destination details.
     * 
     */
    public Optional<Output<List<DbHomeDatabaseDbBackupConfigBackupDestinationDetailArgs>>> backupDestinationDetails() {
        return Optional.ofNullable(this.backupDestinationDetails);
    }

    /**
     * (Updatable) Number of days between the current and the earliest point of recoverability covered by automatic backups. This value applies to automatic backups only. After a new automatic backup has been created, Oracle removes old automatic backups that are created before the window. When the value is updated, it is applied to all existing automatic backups.
     * 
     */
    @Import(name="recoveryWindowInDays")
    private @Nullable Output<Integer> recoveryWindowInDays;

    /**
     * @return (Updatable) Number of days between the current and the earliest point of recoverability covered by automatic backups. This value applies to automatic backups only. After a new automatic backup has been created, Oracle removes old automatic backups that are created before the window. When the value is updated, it is applied to all existing automatic backups.
     * 
     */
    public Optional<Output<Integer>> recoveryWindowInDays() {
        return Optional.ofNullable(this.recoveryWindowInDays);
    }

    private DbHomeDatabaseDbBackupConfigArgs() {}

    private DbHomeDatabaseDbBackupConfigArgs(DbHomeDatabaseDbBackupConfigArgs $) {
        this.autoBackupEnabled = $.autoBackupEnabled;
        this.autoBackupWindow = $.autoBackupWindow;
        this.backupDestinationDetails = $.backupDestinationDetails;
        this.recoveryWindowInDays = $.recoveryWindowInDays;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DbHomeDatabaseDbBackupConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DbHomeDatabaseDbBackupConfigArgs $;

        public Builder() {
            $ = new DbHomeDatabaseDbBackupConfigArgs();
        }

        public Builder(DbHomeDatabaseDbBackupConfigArgs defaults) {
            $ = new DbHomeDatabaseDbBackupConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autoBackupEnabled (Updatable) If set to true, configures automatic backups. If you previously used RMAN or dbcli to configure backups and then you switch to using the Console or the API for backups, a new backup configuration is created and associated with your database. This means that you can no longer rely on your previously configured unmanaged backups to work.
         * 
         * @return builder
         * 
         */
        public Builder autoBackupEnabled(@Nullable Output<Boolean> autoBackupEnabled) {
            $.autoBackupEnabled = autoBackupEnabled;
            return this;
        }

        /**
         * @param autoBackupEnabled (Updatable) If set to true, configures automatic backups. If you previously used RMAN or dbcli to configure backups and then you switch to using the Console or the API for backups, a new backup configuration is created and associated with your database. This means that you can no longer rely on your previously configured unmanaged backups to work.
         * 
         * @return builder
         * 
         */
        public Builder autoBackupEnabled(Boolean autoBackupEnabled) {
            return autoBackupEnabled(Output.of(autoBackupEnabled));
        }

        /**
         * @param autoBackupWindow (Updatable) Time window selected for initiating automatic backup for the database system. There are twelve available two-hour time windows. If no option is selected, a start time between 12:00 AM to 7:00 AM in the region of the database is automatically chosen. For example, if the user selects SLOT_TWO from the enum list, the automatic backup job will start in between 2:00 AM (inclusive) to 4:00 AM (exclusive).  Example: `SLOT_TWO`
         * 
         * @return builder
         * 
         */
        public Builder autoBackupWindow(@Nullable Output<String> autoBackupWindow) {
            $.autoBackupWindow = autoBackupWindow;
            return this;
        }

        /**
         * @param autoBackupWindow (Updatable) Time window selected for initiating automatic backup for the database system. There are twelve available two-hour time windows. If no option is selected, a start time between 12:00 AM to 7:00 AM in the region of the database is automatically chosen. For example, if the user selects SLOT_TWO from the enum list, the automatic backup job will start in between 2:00 AM (inclusive) to 4:00 AM (exclusive).  Example: `SLOT_TWO`
         * 
         * @return builder
         * 
         */
        public Builder autoBackupWindow(String autoBackupWindow) {
            return autoBackupWindow(Output.of(autoBackupWindow));
        }

        /**
         * @param backupDestinationDetails Backup destination details.
         * 
         * @return builder
         * 
         */
        public Builder backupDestinationDetails(@Nullable Output<List<DbHomeDatabaseDbBackupConfigBackupDestinationDetailArgs>> backupDestinationDetails) {
            $.backupDestinationDetails = backupDestinationDetails;
            return this;
        }

        /**
         * @param backupDestinationDetails Backup destination details.
         * 
         * @return builder
         * 
         */
        public Builder backupDestinationDetails(List<DbHomeDatabaseDbBackupConfigBackupDestinationDetailArgs> backupDestinationDetails) {
            return backupDestinationDetails(Output.of(backupDestinationDetails));
        }

        /**
         * @param backupDestinationDetails Backup destination details.
         * 
         * @return builder
         * 
         */
        public Builder backupDestinationDetails(DbHomeDatabaseDbBackupConfigBackupDestinationDetailArgs... backupDestinationDetails) {
            return backupDestinationDetails(List.of(backupDestinationDetails));
        }

        /**
         * @param recoveryWindowInDays (Updatable) Number of days between the current and the earliest point of recoverability covered by automatic backups. This value applies to automatic backups only. After a new automatic backup has been created, Oracle removes old automatic backups that are created before the window. When the value is updated, it is applied to all existing automatic backups.
         * 
         * @return builder
         * 
         */
        public Builder recoveryWindowInDays(@Nullable Output<Integer> recoveryWindowInDays) {
            $.recoveryWindowInDays = recoveryWindowInDays;
            return this;
        }

        /**
         * @param recoveryWindowInDays (Updatable) Number of days between the current and the earliest point of recoverability covered by automatic backups. This value applies to automatic backups only. After a new automatic backup has been created, Oracle removes old automatic backups that are created before the window. When the value is updated, it is applied to all existing automatic backups.
         * 
         * @return builder
         * 
         */
        public Builder recoveryWindowInDays(Integer recoveryWindowInDays) {
            return recoveryWindowInDays(Output.of(recoveryWindowInDays));
        }

        public DbHomeDatabaseDbBackupConfigArgs build() {
            return $;
        }
    }

}