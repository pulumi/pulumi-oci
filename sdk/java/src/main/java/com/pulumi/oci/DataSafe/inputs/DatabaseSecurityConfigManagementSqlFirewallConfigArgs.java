// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DatabaseSecurityConfigManagementSqlFirewallConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatabaseSecurityConfigManagementSqlFirewallConfigArgs Empty = new DatabaseSecurityConfigManagementSqlFirewallConfigArgs();

    @Import(name="excludeJob")
    private @Nullable Output<String> excludeJob;

    public Optional<Output<String>> excludeJob() {
        return Optional.ofNullable(this.excludeJob);
    }

    @Import(name="status")
    private @Nullable Output<String> status;

    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    @Import(name="timeStatusUpdated")
    private @Nullable Output<String> timeStatusUpdated;

    public Optional<Output<String>> timeStatusUpdated() {
        return Optional.ofNullable(this.timeStatusUpdated);
    }

    @Import(name="violationLogAutoPurge")
    private @Nullable Output<String> violationLogAutoPurge;

    public Optional<Output<String>> violationLogAutoPurge() {
        return Optional.ofNullable(this.violationLogAutoPurge);
    }

    private DatabaseSecurityConfigManagementSqlFirewallConfigArgs() {}

    private DatabaseSecurityConfigManagementSqlFirewallConfigArgs(DatabaseSecurityConfigManagementSqlFirewallConfigArgs $) {
        this.excludeJob = $.excludeJob;
        this.status = $.status;
        this.timeStatusUpdated = $.timeStatusUpdated;
        this.violationLogAutoPurge = $.violationLogAutoPurge;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatabaseSecurityConfigManagementSqlFirewallConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatabaseSecurityConfigManagementSqlFirewallConfigArgs $;

        public Builder() {
            $ = new DatabaseSecurityConfigManagementSqlFirewallConfigArgs();
        }

        public Builder(DatabaseSecurityConfigManagementSqlFirewallConfigArgs defaults) {
            $ = new DatabaseSecurityConfigManagementSqlFirewallConfigArgs(Objects.requireNonNull(defaults));
        }

        public Builder excludeJob(@Nullable Output<String> excludeJob) {
            $.excludeJob = excludeJob;
            return this;
        }

        public Builder excludeJob(String excludeJob) {
            return excludeJob(Output.of(excludeJob));
        }

        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        public Builder status(String status) {
            return status(Output.of(status));
        }

        public Builder timeStatusUpdated(@Nullable Output<String> timeStatusUpdated) {
            $.timeStatusUpdated = timeStatusUpdated;
            return this;
        }

        public Builder timeStatusUpdated(String timeStatusUpdated) {
            return timeStatusUpdated(Output.of(timeStatusUpdated));
        }

        public Builder violationLogAutoPurge(@Nullable Output<String> violationLogAutoPurge) {
            $.violationLogAutoPurge = violationLogAutoPurge;
            return this;
        }

        public Builder violationLogAutoPurge(String violationLogAutoPurge) {
            return violationLogAutoPurge(Output.of(violationLogAutoPurge));
        }

        public DatabaseSecurityConfigManagementSqlFirewallConfigArgs build() {
            return $;
        }
    }

}