// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Mysql.inputs.MysqlBackupDbSystemSnapshotBackupPolicyPitrPolicyArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MysqlBackupDbSystemSnapshotBackupPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final MysqlBackupDbSystemSnapshotBackupPolicyArgs Empty = new MysqlBackupDbSystemSnapshotBackupPolicyArgs();

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Specifies if PITR is enabled or disabled.
     * 
     */
    @Import(name="isEnabled")
    private @Nullable Output<Boolean> isEnabled;

    /**
     * @return Specifies if PITR is enabled or disabled.
     * 
     */
    public Optional<Output<Boolean>> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }

    /**
     * The PITR policy for the DB System.
     * 
     */
    @Import(name="pitrPolicies")
    private @Nullable Output<List<MysqlBackupDbSystemSnapshotBackupPolicyPitrPolicyArgs>> pitrPolicies;

    /**
     * @return The PITR policy for the DB System.
     * 
     */
    public Optional<Output<List<MysqlBackupDbSystemSnapshotBackupPolicyPitrPolicyArgs>>> pitrPolicies() {
        return Optional.ofNullable(this.pitrPolicies);
    }

    /**
     * (Updatable) Number of days to retain this backup.
     * 
     */
    @Import(name="retentionInDays")
    private @Nullable Output<Integer> retentionInDays;

    /**
     * @return (Updatable) Number of days to retain this backup.
     * 
     */
    public Optional<Output<Integer>> retentionInDays() {
        return Optional.ofNullable(this.retentionInDays);
    }

    /**
     * The start time of the maintenance window.
     * 
     */
    @Import(name="windowStartTime")
    private @Nullable Output<String> windowStartTime;

    /**
     * @return The start time of the maintenance window.
     * 
     */
    public Optional<Output<String>> windowStartTime() {
        return Optional.ofNullable(this.windowStartTime);
    }

    private MysqlBackupDbSystemSnapshotBackupPolicyArgs() {}

    private MysqlBackupDbSystemSnapshotBackupPolicyArgs(MysqlBackupDbSystemSnapshotBackupPolicyArgs $) {
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.isEnabled = $.isEnabled;
        this.pitrPolicies = $.pitrPolicies;
        this.retentionInDays = $.retentionInDays;
        this.windowStartTime = $.windowStartTime;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MysqlBackupDbSystemSnapshotBackupPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MysqlBackupDbSystemSnapshotBackupPolicyArgs $;

        public Builder() {
            $ = new MysqlBackupDbSystemSnapshotBackupPolicyArgs();
        }

        public Builder(MysqlBackupDbSystemSnapshotBackupPolicyArgs defaults) {
            $ = new MysqlBackupDbSystemSnapshotBackupPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isEnabled Specifies if PITR is enabled or disabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(@Nullable Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled Specifies if PITR is enabled or disabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param pitrPolicies The PITR policy for the DB System.
         * 
         * @return builder
         * 
         */
        public Builder pitrPolicies(@Nullable Output<List<MysqlBackupDbSystemSnapshotBackupPolicyPitrPolicyArgs>> pitrPolicies) {
            $.pitrPolicies = pitrPolicies;
            return this;
        }

        /**
         * @param pitrPolicies The PITR policy for the DB System.
         * 
         * @return builder
         * 
         */
        public Builder pitrPolicies(List<MysqlBackupDbSystemSnapshotBackupPolicyPitrPolicyArgs> pitrPolicies) {
            return pitrPolicies(Output.of(pitrPolicies));
        }

        /**
         * @param pitrPolicies The PITR policy for the DB System.
         * 
         * @return builder
         * 
         */
        public Builder pitrPolicies(MysqlBackupDbSystemSnapshotBackupPolicyPitrPolicyArgs... pitrPolicies) {
            return pitrPolicies(List.of(pitrPolicies));
        }

        /**
         * @param retentionInDays (Updatable) Number of days to retain this backup.
         * 
         * @return builder
         * 
         */
        public Builder retentionInDays(@Nullable Output<Integer> retentionInDays) {
            $.retentionInDays = retentionInDays;
            return this;
        }

        /**
         * @param retentionInDays (Updatable) Number of days to retain this backup.
         * 
         * @return builder
         * 
         */
        public Builder retentionInDays(Integer retentionInDays) {
            return retentionInDays(Output.of(retentionInDays));
        }

        /**
         * @param windowStartTime The start time of the maintenance window.
         * 
         * @return builder
         * 
         */
        public Builder windowStartTime(@Nullable Output<String> windowStartTime) {
            $.windowStartTime = windowStartTime;
            return this;
        }

        /**
         * @param windowStartTime The start time of the maintenance window.
         * 
         * @return builder
         * 
         */
        public Builder windowStartTime(String windowStartTime) {
            return windowStartTime(Output.of(windowStartTime));
        }

        public MysqlBackupDbSystemSnapshotBackupPolicyArgs build() {
            return $;
        }
    }

}