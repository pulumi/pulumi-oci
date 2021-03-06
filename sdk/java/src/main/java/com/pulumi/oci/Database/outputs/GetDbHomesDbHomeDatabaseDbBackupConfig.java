// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetDbHomesDbHomeDatabaseDbBackupConfigBackupDestinationDetail;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDbHomesDbHomeDatabaseDbBackupConfig {
    private final Boolean autoBackupEnabled;
    private final String autoBackupWindow;
    private final List<GetDbHomesDbHomeDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails;
    private final Integer recoveryWindowInDays;

    @CustomType.Constructor
    private GetDbHomesDbHomeDatabaseDbBackupConfig(
        @CustomType.Parameter("autoBackupEnabled") Boolean autoBackupEnabled,
        @CustomType.Parameter("autoBackupWindow") String autoBackupWindow,
        @CustomType.Parameter("backupDestinationDetails") List<GetDbHomesDbHomeDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails,
        @CustomType.Parameter("recoveryWindowInDays") Integer recoveryWindowInDays) {
        this.autoBackupEnabled = autoBackupEnabled;
        this.autoBackupWindow = autoBackupWindow;
        this.backupDestinationDetails = backupDestinationDetails;
        this.recoveryWindowInDays = recoveryWindowInDays;
    }

    public Boolean autoBackupEnabled() {
        return this.autoBackupEnabled;
    }
    public String autoBackupWindow() {
        return this.autoBackupWindow;
    }
    public List<GetDbHomesDbHomeDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails() {
        return this.backupDestinationDetails;
    }
    public Integer recoveryWindowInDays() {
        return this.recoveryWindowInDays;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbHomesDbHomeDatabaseDbBackupConfig defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Boolean autoBackupEnabled;
        private String autoBackupWindow;
        private List<GetDbHomesDbHomeDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails;
        private Integer recoveryWindowInDays;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDbHomesDbHomeDatabaseDbBackupConfig defaults) {
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
        public Builder backupDestinationDetails(List<GetDbHomesDbHomeDatabaseDbBackupConfigBackupDestinationDetail> backupDestinationDetails) {
            this.backupDestinationDetails = Objects.requireNonNull(backupDestinationDetails);
            return this;
        }
        public Builder backupDestinationDetails(GetDbHomesDbHomeDatabaseDbBackupConfigBackupDestinationDetail... backupDestinationDetails) {
            return backupDestinationDetails(List.of(backupDestinationDetails));
        }
        public Builder recoveryWindowInDays(Integer recoveryWindowInDays) {
            this.recoveryWindowInDays = Objects.requireNonNull(recoveryWindowInDays);
            return this;
        }        public GetDbHomesDbHomeDatabaseDbBackupConfig build() {
            return new GetDbHomesDbHomeDatabaseDbBackupConfig(autoBackupEnabled, autoBackupWindow, backupDestinationDetails, recoveryWindowInDays);
        }
    }
}
